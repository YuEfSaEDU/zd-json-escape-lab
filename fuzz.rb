require "active_support"
require "active_support/json"
require "activesupport_json_escape"
require "json"

# Differential fuzzer: ActiveSupport's default JSON encoder vs the C extension.
# Any byte difference is a potential escaping divergence (XSS in <script> JSON).
DEFAULT = ActiveSupport::JSON::Encoding::JSONGemEncoder
CUSTOM  = ActiveSupportJsonEscape::Encoder

def encode_with(klass, value, options)
  old = ActiveSupport.json_encoder
  ActiveSupport.json_encoder = klass
  ActiveSupport::JSON.encode(value, options)
ensure
  ActiveSupport.json_encoder = old
end

CHARS = ["<", ">", "&", "\u2028", "\u2029", "é", "漢", "'", '"', "\\", "\n", "\r", "\t", " ", "a", "Z", "0", "\u0000", "\u007f", "😀"]

def rand_string
  Array.new(rand(0..60)) { CHARS.sample }.join
end

def rand_value(depth = 0)
  return rand_string if depth > 3 || rand < 0.55
  case rand(4)
  when 0 then Array.new(rand(0..5)) { rand_value(depth + 1) }
  when 1 then Hash[Array.new(rand(0..5)) { [rand_string, rand_value(depth + 1)] }]
  when 2 then [true, false, nil, rand(-1_000_000..1_000_000), rand * 1000].sample
  else rand_string
  end
end

def set_flags(html:, js:)
  enc = ActiveSupport::JSON::Encoding
  enc.escape_html_entities_in_json = html
  enc.escape_js_separators_in_json = js
end

configs = [
  { html: true,  js: true  },
  { html: true,  js: false },
  { html: false, js: true  },
  { html: false, js: false }
]
options_list = [{}, { escape: false }, { escape_html_entities: false }, { escape_html_entities: true }]

failures = 0
checks = 0
5000.times do |i|
  value = rand_value
  configs.each do |cfg|
    set_flags(**cfg)
    options_list.each do |opts|
      a = begin
        encode_with(DEFAULT, value, opts)
      rescue => e
        "RAISE:#{e.class}:#{e.message}"
      end
      b = begin
        encode_with(CUSTOM, value, opts)
      rescue => e
        "RAISE:#{e.class}:#{e.message}"
      end
      checks += 1
      next if a == b
      failures += 1
      puts "MISMATCH i=#{i} cfg=#{cfg} opts=#{opts}"
      puts "  value=#{value.inspect}"
      puts "  AS   =#{a.inspect}"
      puts "  C    =#{b.inspect}"
      exit 2 if failures >= 20
    end
  end
end

# Explicit edge cases: frozen input, invalid bytes, separator at buffer edge.
edge_values = [
  "abc".freeze,
  "<>&",
  "\u2028",
  "\u2029",
  "a\u2028b\u2029c",
  "\xFF".b,
  "\xFF<>&".b,
  "x" * 4096 + "<",
  "<" * 4096,
  "\u2028" * 4096
]
edge_values.each_with_index do |value, i|
  configs.each do |cfg|
    set_flags(**cfg)
    a = begin; encode_with(DEFAULT, value, {}); rescue => e; "RAISE:#{e.class}:#{e.message}"; end
    b = begin; encode_with(CUSTOM, value, {}); rescue => e; "RAISE:#{e.class}:#{e.message}"; end
    checks += 1
    next if a == b
    failures += 1
    puts "EDGE MISMATCH i=#{i} cfg=#{cfg} value=#{value.inspect[0,120]}"
    puts "  AS=#{a.inspect[0,300]}"
    puts "  C =#{b.inspect[0,300]}"
  end
end

puts "CHECKS=#{checks} FAILURES=#{failures}"
exit(failures.zero? ? 0 : 1)
