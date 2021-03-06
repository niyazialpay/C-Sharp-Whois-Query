/*
Muhammed Niyazi ALPAY
https://niyazialpay.com
https://api.niyazialpay.com/whois/yourdomainname.tld
*/
using System;
using System.Text;
using System.Net.Sockets;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Collections;

namespace Cryptograph_Whois_DNS_Tools
{
    public class whois
    {
        private static readonly Hashtable whoisServers =
            new Hashtable {
                { "com", "whois.verisign-grs.com" },
                { "net", "whois.verisign-grs.com" },
                { "org","whois.publicinterestregistry.net" },
                { "info","whois.afilias.info" },
                { "biz","whois.neulevel.biz" },
                { "us","whois.nic.us" },
                { "uk","whois.nic.uk" },
                { "ca","whois.cira.ca" },
                { "tel","whois.nic.tel" },
                { "ie","whois.iedr.ie"},
                { "it","whois.nic.it" },
                { "li","whois.nic.li" },
                { "no","whois.norid.no" },
                { "cc","whois.nic.cc" },
                { "eu","whois.eu" },
                { "nu","whois.nic.nu" },
                { "au","whois.aunic.net" },
                { "de","whois.nic.de" },
                { "ws","whois.nic.ws" },
                { "sc","whois2.afilias-grs.net" },
                { "mobi","whois.dotmobiregistry.net" },
                { "pro","whois.registry.pro" },
                { "edu","whois.educause.net" },
                { "tv","whois.nic.tv" },
                { "travel","whois.nic.travel" },
                { "name", "whois.nic.name" },
                { "in", "whois.registry.in"},
                { "me","whois.nic.me" },
                { "at","whois.nic.at" },
                { "be","whois.dns.be" },
                { "cn","whois.cnnic.cn" },
                { "asia","whois.nic.asia" },
                { "ru","whois.ripn.ru" },
                { "ro","whois.rotld.ro"},
                { "aero","whois.aero" },
                { "fr","whois.nic.fr" },
                { "se","whois.nic.se" },
                { "nl","whois.sidn.nl" },
                { "nz","whois.srs.net.nz" },
                { "mx","whois.nic.mx" },
                { "tw","whois.apnic.net" },
                { "ch","whois.nic.ch" },
                { "hk","whois.hknic.net.hk" },
                { "ac","whois.nic.ac" },
                { "ae","whois.nic.ae" },
                { "af","whois.nic.af" },
                { "ag","whois.nic.ag" },
                { "al","whois.ripe.net" },
                { "am","whois.amnic.net" },
                { "as","whois.nic.as" },
                { "az","whois.ripe.net" },
                { "ba","whois.ripe.net" },
                { "bg","whois.register.bg" },
                { "bi","whois.nic.bi" },
                { "bj","www.nic.bj" },
                { "br","whois.nic.br" },
                { "bt","whois.netnames.net" },
                { "by","whois.ripe.net" },
                { "bz","whois.belizenic.bz" },
                { "cd","whois.nic.cd" },
                { "ck","whois.nic.ck" },
                { "co","whois.nic.co" },
                { "cl","nic.cl" },
                { "coop","whois.nic.coop" },
                { "cx","whois.nic.cx" },
                { "cy","whois.ripe.net" },
                { "cz","whois.nic.cz" },
                { "dk","whois.dk-hostmaster.dk" },
                { "dm","whois.nic.cx" },
                { "dz","whois.ripe.net" },
                { "ee","whois.eenet.ee" },
                { "eg","whois.ripe.net" },
                { "es","whois.nic.es" },
                { "fi","whois.ficora.fi" },
                { "fo","whois.ripe.net" },
                { "gb","whois.ripe.net" },
                { "ge", "whois.ripe.net" },
                { "gl", "whois.ripe.net" },
                { "gm","whois.ripe.net" },
                { "gov","whois.nic.gov" },
                { "gr","whois.ripe.net" },
                { "gs","whois.adamsnames.tc" },
                { "hm","whois.registry.hm" },
                { "hn","whois2.afilias-grs.net" },
                { "hr","whois.ripe.net" },
                { "hu","whois.ripe.net" },
                { "il","whois.isoc.org.il" },
                { "int","whois.isi.edu" },
                { "ig","vrx.net" },
                { "ir","whois.nic.ir" },
                { "is","whois.isnic.is" },
                { "je","whois.je" },
                { "jp","whois.jprs.jp" },
                { "kg","whois.domain.kg" },
                { "kr","whois.nic.or.kr" },
                { "la","whois2.afilias-grs.net" },
                { "lt","whois.domreg.lt" },
                { "lu","whois.restena.lu" },
                { "lv","whois.nic.lv" },
                { "ly","whois.lydomains.com" },
                { "ma","whois.iam.net.ma" },
                { "mc","whois.ripe.net" },
                { "md","whois.nic.md" },
                { "mil","whois.nic.mil" },
                { "mk","whois.ripe.net" },
                { "ms","whois.nic.ms" },
                { "mt","whois.ripe.net" },
                { "mu","whois.nic.mu" },
                { "my","whois.mynic.net.my" },
                { "nf","whois.nic.cx" },
                { "pl","whois.dns.pl" },
                { "pr","whois.nic.pr" },
                { "pt","whois.dns.pt" },
                { "sa","saudinic.net.sa" },
                { "sb","whois.nic.net.sb" },
                { "sg","whois.nic.net.sg" },
                { "sh","whois.nic.sh"},
                { "si","whois.arnes.si" },
                { "sk","whois.sk-nic.sk" },
                { "sm","whois.ripe.net" },
                { "st","whois.nic.st" },
                { "su","whois.ripn.net" },
                { "tc","whois.adamsnames.tc" },
                { "tf","whois.nic.tf" },
                { "th","whois.thnic.net" },
                { "tj","whois.nic.tj" },
                { "tk","whois.nic.tk" },
                { "tl", "whois.domains.tl" },
                { "tm","whois.nic.tm" },
                { "tn","whois.ripe.net" },
                { "to","whois.tonic.to" },
                { "tp","whois.domains.tl" },
                { "tr","whois.nic.tr" },
                { "ua","whois.ripe.net" },
                { "uy","nic.uy" },
                { "uz","whois.cctld.uz" },
                { "va","whois.ripe.net" },
                { "vc","whois2.afilias-grs.net"},
                { "ve","whois.nic.ve"},
                { "vg","whois.adamsnames.tc"},
                { "yu","whois.ripe.net" },
                { "science","whois.iana.org" },
                { "xyz", "whois.nic.xyz" },
                { "ist", "whois.nic.istanbul" },
                { "istanbul", "whois.nic.istanbul" }
            };

        private static string GetDomainName(string url)
        {
            var doubleSlashesIndex = url.IndexOf("://");
            var start = doubleSlashesIndex != -1 ? doubleSlashesIndex + "://".Length : 0;
            var end = url.IndexOf("/", start);
            if (end == -1)
                end = url.Length;

            string domainname = url.Substring(start, end - start);
            if (domainname.StartsWith("www."))
                domainname = domainname.Substring("www.".Length);
            return domainname;
        }

        private static string GetDomainTld(string host)
        {
            var p = host.LastIndexOf(".");
            var domain = host.Substring(p + 1);
            return domain;
        }

        private static string getWhoisServer(string tld)
            => (whoisServers[tld]
            ?? whoisServers["com"])
            as string;

        public static string query(string domain)
        {
            try
            {
                string domainname = GetDomainName(domain);
                string whoisserver = getWhoisServer(GetDomainTld(domain));
                string strDomain = domainname + "\r\n";
                byte[] arrDomain = Encoding.ASCII.GetBytes(strDomain);
                using (TcpClient TCPC = new TcpClient(whoisserver, 43))
                {
                    TCPC.GetStream().Write(arrDomain, 0, strDomain.Length);
                    using (StreamReader objSR = new StreamReader(TCPC.GetStream(), Encoding.ASCII))
                        return objSR.ReadToEnd();//Regex.Replace(objSR.ReadToEnd(), "\n", "<br>");
                }
            }
            catch (Exception ex)
            {
                return ex.ToString();
            }
        }
    }
}