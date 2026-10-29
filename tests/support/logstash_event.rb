# Emulates only the documented Event field API. Real LogStash::Event behavior
# and pipeline parsing are additionally checked in the isolated Docker test.
class Event
  attr_reader :data
  def initialize(data)
    @data = data
  end
  def path(key)
    key.start_with?('[') ? key.scan(/\[([^\]]+)\]/).flatten : [key]
  end
  def get(key)
    path(key).reduce(@data) { |value, part| value.is_a?(Hash) ? value[part] : nil }
  end
  def set(key, value)
    parts = path(key)
    parent = parts[0...-1].reduce(@data) { |hash, part| hash[part] ||= {} }
    parent[parts[-1]] = value
  end
  def remove(key)
    parts = path(key)
    parent = parts[0...-1].reduce(@data) { |value, part| value.is_a?(Hash) ? value[part] : nil }
    parent.delete(parts[-1]) if parent.is_a?(Hash)
  end
  def tag(value)
    @data['tags'] ||= []
    @data['tags'] << value
  end
end
