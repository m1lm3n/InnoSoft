<#
    targets.psd1

    The one place where domains and their controllers are described.
    deploy.ps1, run-remote.ps1 and Fix-NlaDependency.ps1 all read this file,
    so a renamed controller is a one line change.

    Fields
        Server   the controller the toolkits talk to and are deployed onto
        Trusted  $false when the domain has no trust with the management
                 domain. Kerberos cannot work there, so WinRM needs NTLM and
                 the host must be listed in TrustedHosts.
                 Verified 13.08.2026 with: nltest /domain_trusts /all_trusts /v
                   core64.com trusts kkk.lo, xxx.lo, a.lo, c.lo
                   nnn.lo and ttt.lo are standalone forests, no trust at all
        Extra    further controllers in the same domain. Used for the
                 TrustedHosts list, and by deploy.ps1 with -IncludeExtra.
        Note     free text, shown by -List

    This is a data file: it may only contain a hash table literal, no code.
#>

@{
    'nnn.lo'     = @{
        Server  = 'dc-nnn.nnn.lo'
        Trusted = $false
        Extra   = @('dc2-nnn.nnn.lo')
        Note    = 'users: reten, conversion, sales. No trust, NTLM only'
    }

    'kkk.lo'     = @{
        Server  = 'dc-kkk.kkk.lo'
        Trusted = $true
        Extra   = @('dc2-kkk.kkk.lo')
        Note    = 'scouts, operators. Two RODCs in India and Kazakhstan are dead'
    }

    'xxx.lo'     = @{
        Server  = 'dc-xxx.xxx.lo'
        Trusted = $true
        Extra   = @('dc2-xxx.xxx.lo')
        Note    = 'admin Silver. RODC in Taiwan is dead'
    }

    'ttt.lo'     = @{
        Server  = 'dc-ttt.ttt.lo'
        Trusted = $false
        Note    = 'single DC. No trust, NTLM only'
    }

    'a.lo'       = @{
        Server  = 'dc.a.lo'
        Trusted = $true
        Note    = 'auth for OnlyOffice and Nextcloud, single DC'
    }

    'core64.com' = @{
        Server  = 'dc-dc1.core64.com'
        Trusted = $true
        Extra   = @('dc-dc2.core64.com')
        Note    = 'management domain'
    }
}