# encoding: utf-8
# author: Gary Bright @username-is-already-taken2

# check for a Windows role (a collection of windows-features) on a windows server
# Usage:
# describe windows_role('AD-Domain-Services') do
#   it{ should be_installed }
# end
#
# Example list of roles from a 2012 R2 Server
#
# RoleName                Installed
# --------                ---------
# AD-Certificate              False
# AD-Domain-Services          False
# ADFS-Federation             False
# ADLDS                       False
# ADRMS                       False
# Application-Server          False
# DHCP                        False
# DNS                         False
# Fax                         False
# FileAndStorage-Services      True
# Hyper-V                     False
# NPAS                        False
# Print-Services              False
# RemoteAccess                False
# Remote-Desktop-Services     False
# VolumeActivation            False
# Web-Server                   True
# WDS                         False
# ServerEssentialsRole        False
# UpdateServices              False
#
module Inspec::Resources
  class WindowsRole < Inspec.resource(1)
    name 'windows_role'
    desc 'This is PoC InSpec Resource for @amunoz951 to audit the roles enabled on a windows server.'
    example "
      describe windows_role('AD-Domain-Services') do
        it{ should_not be_installed }
      end
      describe windows_role('Web-Server') do
        it{ should be_installed }
      end
    "

    def initialize(role)
      @role = role
      @cache = nil

      # verify that this resource is only supported on Windows
      return skip_resource 'The `windows_role` resource is not supported on your OS.' unless inspec.os.windows?
    end

    # returns true if the role is installed
    def installed?
      info[@role.downcase] == true
    end

    # returns the state of all roles
    def info
      return @cache if !@cache.nil?
      role_cmd = "$Hash = @{};Get-WindowsFeature | Where-Object { $_.FeatureType -eq 'Role' } | Select-Object Name,Installed | % { $Hash += @{$_.Name.ToLower()=$_.Installed} };$Hash | ConvertTo-Json -Compress"
      cmd = inspec.command(role_cmd)

      begin
        params = JSON.parse(cmd.stdout)
      rescue JSON::ParserError => _e
        return @cache
      end

      @cache = params
    end

    def to_s
      "Windows Role '#{@role}'"
    end
  end
end
