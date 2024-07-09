#
#  FACT(S):     aix_pwaudit
#
#  PURPOSE:     This custom fact returns a hash of values from the default stanza
#               of the /etc/security/user file.  Sadly, "lssec" doesn't do this
#               all at once, so it's multiple runs of the same program/code.
#
#  RETURNS:     (hash)
#
#  AUTHOR:      Chris Petersen, Crystallized Software
#
#  DATE:        September 17, 2023
#
#  NOTES:       Myriad names and acronyms are trademarked or copyrighted by IBM
#               including but not limited to IBM, PowerHA, AIX, RSCT (Reliable,
#               Scalable Cluster Technology), and CAA (Cluster-Aware AIX).  All
#               rights to such names and acronyms belong with their owner.
#
#-------------------------------------------------------------------------------
#
#  LAST MOD:    (never)
#
#  MODIFICATION HISTORY:
#
#       (none)
#
#-------------------------------------------------------------------------------
#
Facter.add(:aix_pwaudit) do
    #  This only applies to the AIX operating system
    confine :osfamily => 'AIX'

    #  Define an unfortunate value for our default return
    l_aixPwauditData = {}

    #  Do the work - same thing over and over for the things we want to report
    setcode do
        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a histexpire 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default histexpire')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['histexpire']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a histsize 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default histsize')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['histsize']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a loginretries 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default loginretries')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['loginretries']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a maxage 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default maxage')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['maxage']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a maxexpired 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default maxexpired')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['maxexpired']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a maxrepeats 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default maxrepeats')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['maxrepeats']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minage 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minage')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minage']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minalpha 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minalpha')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minalpha']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minloweralpha 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minloweralpha')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minloweralpha']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minupperalpha 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minupperalpha')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minupperalpha']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a mindiff 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default mindiff')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['mindiff']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minlen 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minlen')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minlen']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minother 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minother')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minother']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a mindigit 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default mindigit')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['mindigit']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a minspecialchar 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default minspecialchar')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['minspecialchar']=l_list[1]
                end
            end
        end

        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a pwdchecks 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default pwdchecks')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['pwdchecks']=l_list[1]
                end
            end
        end


        #  Run the command to grab one piece of data from the default stanza of /etc/security/user
        l_lines = Facter::Util::Resolution.exec('/usr/bin/lssec -f /etc/security/user -s default -a pwdwarntime 2>/dev/null')

        #  Loop over the lines that were returned
        l_lines && l_lines.split('\n').each do |l_oneLine|
            #  Strip leading and trailing whitespace and split on an equals sign
            l_list = l_oneLine.strip().split('=')

            #  If the first part matches, look at the second part
            if (l_list[0] == 'default pwdwarntime')
                #  If the second part is non-empty, copy it in
                if ((l_list[1].nil? == false) and (l_list[1] != ''))
                    l_aixPwauditData['pwdwarntime']=l_list[1]
                end
            end
        end

        #  Implicitly return the contents of the variable
        l_aixPwauditData
    end
end
