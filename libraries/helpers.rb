module FirewallCookbook
  module Helpers
    def dport_calc(new_resource)
      new_resource.dest_port || new_resource.port
    end

    def port_to_s(p)
      if p && p.is_a?(Integer)
        p.to_s
      elsif p && p.is_a?(Array)
        p.join(',')
      elsif p && p.is_a?(Range)
        "#{p.first}:#{p.last}"
      end
    end

    def ip_with_mask(new_resource, ip)
      if ip.include?('/')
        ip
      elsif ipv4_rule?(new_resource)
        "#{ip}/32"
      elsif ipv6_rule?(new_resource)
        "#{ip}/128"
      else
        ip
      end
    end

    def ipv4_rule?(new_resource)
      if (new_resource.source && IPAddr.new(new_resource.source).ipv4?) ||
         (new_resource.destination && IPAddr.new(new_resource.destination).ipv4?)
        true
      else
        false
      end
    end

    def ipv6_rule?(new_resource)
      if (new_resource.source && IPAddr.new(new_resource.source).ipv6?) ||
         (new_resource.destination && IPAddr.new(new_resource.destination).ipv6?)
        true
      else
        false
      end
    end
  end
end
