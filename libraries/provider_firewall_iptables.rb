#
# Author:: Seth Chisamore (<schisamo@opscode.com>)
# Cookbook Name:: firewall
# Resource:: default
#
# Copyright:: 2011, Opscode, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
require 'poise'

class Chef
  class Provider::FirewallIptables < Provider
    include Poise
    include Chef::Mixin::ShellOut
    include FirewallCookbook::Helpers

    def action_enable
      converge_by("install package #{package_name} and default DROP if no rules exist") do
        package package_name do
          action :install
        end

        service service_name do
          action [:enable, :start]
        end

        # prints all the firewall rules
        # pp new_resource.subresources
        log_current_iptables

        all_rules = {}
        all_rules["*filter"] = 0
        new_resource.subresources.each do |rule_resource|
          weight = rule_resource.position || 50
          all_rules["-A #{build_firewall_rule(rule_resource)}"] = weight
        end
        all_rules["COMMIT"] = 100

        file '/etc/sysconfig/iptables' do
          content all_rules.sort_by { |k,v| v }.map { |k,v| k }.join("\n")
          notifies :reload, 'service[iptables]', :delayed
        end

        if active?
          Chef::Log.info("#{new_resource} already enabled.")
        else
          Chef::Log.debug("#{new_resource} is about to be enabled")
          shell_out!('iptables -P INPUT DROP')
          shell_out!('iptables -P OUTPUT DROP')
          shell_out!('iptables -P FORWARD DROP')

          shell_out!('ip6tables -P INPUT DROP')
          shell_out!('ip6tables -P OUTPUT DROP')
          shell_out!('ip6tables -P FORWARD DROP')
          Chef::Log.info("#{new_resource} enabled.")
          new_resource.updated_by_last_action(true)
        end
      end
    end

    def action_disable
      if active?
        shell_out!('iptables -P INPUT ACCEPT')
        shell_out!('iptables -P OUTPUT ACCEPT')
        shell_out!('iptables -P FORWARD ACCEPT')
        shell_out!('iptables -F')

        shell_out!('ip6tables -P INPUT ACCEPT')
        shell_out!('ip6tables -P OUTPUT ACCEPT')
        shell_out!('ip6tables -P FORWARD ACCEPT')
        shell_out!('ip6tables -F')
        Chef::Log.info("#{new_resource} disabled")
        new_resource.updated_by_last_action(true)
      else
        Chef::Log.debug("#{new_resource} already disabled.")
      end

      service service_name do
        action [:disable, :stop]
      end
    end

    def action_flush
      shell_out!('iptables -F')
      shell_out!('ip6tables -F')
      Chef::Log.info("#{new_resource} flushed.")
    end

    def action_save
      shell_out!("service #{service_name} save")
      # iptables-persistent does ipv6 inside the iptables init script
      shell_out!('service ip6tables save') unless ubuntu?
      Chef::Log.info("#{new_resource} saved.")
    end

    private

    def active?
      @active ||= begin
        cmd = shell_out!('iptables-save')
        cmd.stdout =~ /INPUT ACCEPT/
      end
      @active_v6 ||= begin
        cmd = shell_out!('ip6tables-save')
        cmd.stdout =~ /INPUT ACCEPT/
      end
      @active && @active_v6
    end

    def log_current_iptables
      cmdstr = 'iptables -L'
      Chef::Log.info("#{new_resource} log_current_iptables (#{cmdstr}):")
      cmd = shell_out!(cmdstr)
      Chef::Log.info(cmd.inspect)
      cmdstr = 'ip6tables -L'
      Chef::Log.info("#{new_resource} log_current_iptables (#{cmdstr}):")
      cmd = shell_out!(cmdstr)
      Chef::Log.info(cmd.inspect)
    rescue
      Chef::Log.info("#{new_resource} log_current_iptables failed!")
    end

    def package_name
      if ubuntu?
        'iptables-persistent'
      else
        'iptables'
      end
    end

    def service_name
      if ubuntu?
        'iptables-persistent'
      else
        'iptables'
      end
    end

    def ubuntu?
      node['platform'] == 'ubuntu'
    end

    CHAIN = { :in => 'INPUT', :out => 'OUTPUT', :pre => 'PREROUTING', :post => 'POSTROUTING' } unless defined? CHAIN # , nil => "FORWARD"}
    TARGET = { :allow => 'ACCEPT', :reject => 'REJECT', :deny => 'DROP', :masquerade => 'MASQUERADE', :redirect => 'REDIRECT', :log => 'LOG --log-prefix "iptables: " --log-level 7' } unless defined? TARGET

    def build_firewall_rule(rule_resource)
      el5 = (node['platform'] == 'rhel' || node['platform'] == 'centos') && Gem::Dependency.new('', '~> 5.0').match?('', node['platform_version'])
      if rule_resource.raw
        firewall_rule = rule_resource.raw.strip
      else
        firewall_rule = ''
        if rule_resource.direction
          firewall_rule << "#{CHAIN[rule_resource.direction.to_sym]} "
        else
          firewall_rule << 'FORWARD '
        end

        if [:pre, :post].include?(rule_resource.direction)
          firewall_rule << '-t nat '
        end

        # Iptables order of prameters is important here see example output below:
        # -A INPUT -s 1.2.3.4/32 -d 5.6.7.8/32 -i lo -p tcp -m tcp -m state --state NEW -m comment --comment "hello" -j DROP
        firewall_rule << "-s #{ip_with_mask(rule_resource, rule_resource.source)} " if rule_resource.source && rule_resource.source != '0.0.0.0/0'
        firewall_rule << "-d #{rule_resource.destination} " if rule_resource.destination

        firewall_rule << "-i #{rule_resource.interface} " if rule_resource.interface
        firewall_rule << "-o #{rule_resource.dest_interface} " if rule_resource.dest_interface

        firewall_rule << "-p #{rule_resource.protocol} " if rule_resource.protocol
        firewall_rule << '-m tcp ' if rule_resource.protocol.to_s.to_sym == :tcp

        # using multiport here allows us to simplify our greps and rule building
        firewall_rule << "-m multiport --sports #{port_to_s(rule_resource.source_port)} " if rule_resource.source_port
        firewall_rule << "-m multiport --dports #{port_to_s(dport_calc(rule_resource))} " if dport_calc(rule_resource)

        firewall_rule << "-m state --state #{rule_resource.stateful.is_a?(Array) ? rule_resource.stateful.join(',').upcase : rule_resource.stateful.upcase} " if rule_resource.stateful
        # the comments extension is not available for ip6tables on rhel/centos 5
        unless el5 && ipv6_rule?(rule_resource)
          firewall_rule << "-m comment --comment \"#{rule_resource.description}\" "
        end
        act = rule_resource.action
        act_sym = act.kind_of?(Array) ? act.first : act
        firewall_rule << "-j #{TARGET[act_sym]} "
        firewall_rule << "--to-ports #{rule_resource.redirect_port} " if rule_resource.action == :redirect
        firewall_rule.strip!
      end
      firewall_rule
    end

  end
end
