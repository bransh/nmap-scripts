local shortport = require "shortport"
local stdnse = require "stdnse"
local smtp = require "smtp"
local dns = require "dns"

description = [[
Verifies if the DNS MX record for the SMTP banner's domain points to the current SMTP server. 
If a deviation is observed, then it is possible that the service is being dangerously exposed.
It is particular useful for those scenarios where a company is using a cloud based anti-spam
gateway solution and inadvertently left their SMTP service exposed to the Internet, allowing
an attacker to potentially bypass the Anti-Spam solution, to reach the internal user with
phishing emails.
]]

---
-- @usage
-- nmap -p 25,465,587 --script smtp-antispam-bypass <target>
--
-- @output
-- PORT   STATE SERVICE REASON  VERSION
-- 25/tcp open  smtp    syn-ack Microsoft Exchange smtpd
-- | smtp-antispam-bypass: 
-- |   SMTP Server: 192.168.10.100
-- |   SMTP FQDN (from banner): EXCH01.domain.com
-- |   Domain: domain.com
-- |   MX Record(s): 
-- |     10:je-smtp-inbound-2.mimecast-offshore.com
-- |     10:je-smtp-inbound-1.mimecast-offshore.com
-- |   MX Record(s) IP(s): 
-- |     213.167.81.36
-- |     213.167.75.36
-- |     213.167.81.36
-- |     213.167.75.36
-- |_  [!] Warning: The SMTP server is not part of the DNS MX Records. If the domain is using an anti-spam 
-- solution as mail gateway (check the MX Records), then the exposed SMTP service may be used by an attacker 
-- to bypass the anti-spam solution and reach the company's user mailboxes directly.

author = "@br4nsh"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service({25, 465, 587}, {"smtp", "smtps", "submission"})

-- Gets domain info from FQDN
--
-- @param string containing the target FQDN
-- @return status boolean
-- @return (response table containing <code>fqdn</code>, <code>fqdn_A</code>, 
-- <code>domain</code>, <code>MX</code>, <code>MX_A</code> if status is true) or 
-- (string containing the error message if status is false)
local function getDomainInfo(domain)
    local status, response
    local target = domain
    local base_domain
    local return_table = {}
    local err_msg

    -- First: let's check if the FQDN actually exists (could be internal)
    stdnse.debug1("[*] getDomainInfo(): Requesting A record for '%s'", target)
    status, response = dns.query(target, {dtype='A'})
    if status then
        stdnse.debug1( "[+] getDomainInfo(): IP address of '%s': '%s'", target, response)
        return_table["fqdn"] = target
        return_table["fqdn_A"] = response
    else
        stdnse.debug1("[-] getDomainInfo(): FQDN does not exist, may be an internal hostname")
        err_msg = "The FQDN '" .. target .. "' does not exists."
        return false, err_msg
    end

    -- Second: let's find the base domain name
    while true do
        stdnse.debug1("[*] getDomainInfo(): Requesting SOA record for '%s'", target)
        status, response = dns.query(target, {dtype='SOA', retPkt=true})
        if status == true and response.answers[1].dtype == dns.types['SOA'] then
            stdnse.debug1("[+] getDomainInfo(): Base domain found: '%s'", response.answers[1].dname)
            base_domain = response.answers[1].dname
            return_table["domain"] = base_domain
            break
        else
            -- Try removing the host portion until next "."
            target = string.sub(target, string.find(target, "%.") + 1)
            -- If no "." char exists in in the new target, no need to try further 
            -- (don't want to try with ".com", right?)
            if string.find(target, "%.") == nil then
                err_msg = "The base domain for '" .. target .. "' cannot be identified."
                return false, err_msg
            end
        end
    end

    -- Third: let's search the MX record for the base domain
    stdnse.debug1("[*] getDomainInfo(): Requesting MX record for domain '%s'", base_domain)
    status, response = dns.query(base_domain, {dtype='MX', retAll=true})
    if status then
        stdnse.debug1("[+] getDomainInfo(): %d MX record(s) found", #response)
        return_table["MX"] = response
    else
        err_msg = "The DNS MX records for the domain '" .. base_domain .. "' does not"
        return false, err_msg
    end

    -- Fourth: let's get the IP addresses of the MX records
    local ips = {}
    stdnse.debug1("[*] getDomainInfo(): Requesting A record for MX records")
    -- Go over MX records
    for _,v in pairs(return_table["MX"]) do
        -- Gets the value after the ":" (priority of MX)
        local mail_server_list = stdnse.strsplit(":", v)
        local s, r
        if (#mail_server_list > 1) then
            s, r = dns.query(mail_server_list[2], {dtype='A', retAll=true})
            if s then
                -- Go over A records
                for _,v2 in pairs(r) do
                    stdnse.debug1("[*] getDomainInfo(): IP found: '%s'", v2)
                    ips[#ips+1] = v2
                end
            end
        end
    end
    return_table["MX_A"] = ips

    return true, return_table
end

-- Main function
action = function(host, port)
    local output = stdnse.output_table()
    local client_domain = "example.org"
    local pepe = false

    -- Connects to the SMTP server
    local socket, banner = smtp.connect(host, port, {ssl=true, timeout=5000, recv_before=true})

    -- If the connection failed, then finishes
    if not socket then
        stdnse.debug1("[-] Failed to connect to SMTP server.")
        return nil
    end

    -- Tries to get the FQDN from the SMTP banner
    local srvname = string.match(banner, "%d+%s([%w]+[%w%.-]*)")
    if not srvname then
        local status, response = smtp.ehlo(socket, domain)
        if status then
            srvname = string.match(response, "%d+%-([%w]+[%w%.-]*)")
            if not srvname then
                stdnse.debug1("[-] Failed to get the service banner.")
                return nil
            end
        end
    end
    stdnse.debug1("[+] FQDN extracted from server banner: '%s'", srvname)

    --fqdn = generic113.mxout.managed.com
    -- Gets domain information
    local status, response = getDomainInfo(srvname)

    local output = stdnse.output_table()
    local message
    if status then
        -- Build the output
        output["SMTP Server"] = host.ip
        output["SMTP FQDN (from banner)"] = srvname
        output["SMTP FQDN IP"] = response["FQDN_A"]
        output["Domain"] = response["domain"]
        output["MX Record(s)"] = response["MX"]
        output["MX Record(s) IP(s)"] = response["MX_A"]

        -- Let's check if our host is one of the MX records
        local found = false
        if status then
            for _,v in pairs(response["MX_A"]) do
                if v == host.ip then
                    found = true
                    break
                end
            end
            if not found then
                message = "The SMTP server is not part of the DNS MX Records. If the domain is using "
                message = message .. "an anti-spam solution as mail gateway (check the MX Records), then "
                message = message .. "the exposed SMTP service may be used by an attacker to bypass the "
                message = message .. "anti-spam solution and reach the company's user mailboxes directly."
                output["[!] Warning"] = message
            end
        end
    else
        message = "An error ocurred and the analyis cannot be completed."
        output["[-] ERROR"] = message
        output["[!] DESCRIPTION"] = response
    end

    return output 
end