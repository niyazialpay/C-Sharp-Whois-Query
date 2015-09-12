/*
Muhammed Niyazi ALPAY
https://niyazialpay.com
https://api.niyazialpay.com/whois/yourdomainname.tld
*/
using System;
using System.Text;
using System.Net.Sockets;
using System.IO;
using System.Text.RegularExpressions;

namespace Cryptograph_Whois_DNS_Tools
{
    public class whois
    {
        private string GetDomainName(string url)
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

        private string GetDomainTld(string host)
        {
            var p = host.LastIndexOf(".");
            var domain = host.Substring(p + 1);
            return domain;
        }

        private string getWhoisServer(string tld)
        {
            string[,] whoisServers = new string[143, 2] {
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
                { "xyz", "whois.nic.xyz" }
            };


            if (tld == "com")
            {
                return whoisServers[0, 1];
            }
            else if (tld == "net")
            {
                return whoisServers[1, 1];
            }
            else if (tld == "org")
            {
                return whoisServers[2, 1];
            }
            else if (tld == "info")
            {
                return whoisServers[3, 1];
            }
            else if (tld == "biz")
            {
                return whoisServers[4, 1];
            }
            else if (tld == "us")
            {
                return whoisServers[5, 1];
            }
            else if (tld == "uk")
            {
                return whoisServers[6, 1];
            }
            else if (tld == "ca")
            {
                return whoisServers[7, 1];
            }
            else if (tld == "tel")
            {
                return whoisServers[8, 1];
            }
            else if (tld == "ie")
            {
                return whoisServers[9, 1];
            }
            else if (tld == "it")
            {
                return whoisServers[10, 1];
            }
            else if (tld == "li")
            {
                return whoisServers[11, 1];
            }
            else if (tld == "no")
            {
                return whoisServers[12, 1];
            }
            else if (tld == "cc")
            {
                return whoisServers[13, 1];
            }
            else if (tld == "eu")
            {
                return whoisServers[14, 1];
            }
            else if (tld == "nu")
            {
                return whoisServers[15, 1];
            }
            else if (tld == "au")
            {
                return whoisServers[16, 1];
            }
            else if (tld == "de")
            {
                return whoisServers[17, 1];
            }
            else if (tld == "ws")
            {
                return whoisServers[18, 1];
            }
            else if (tld == "sc")
            {
                return whoisServers[19, 1];
            }
            else if (tld == "mobi")
            {
                return whoisServers[20, 1];
            }
            else if (tld == "pro")
            {
                return whoisServers[21, 1];
            }
            else if (tld == "edu")
            {
                return whoisServers[22, 1];
            }
            else if (tld == "tv")
            {
                return whoisServers[23, 1];
            }
            else if (tld == "travel")
            {
                return whoisServers[24, 1];
            }
            else if (tld == "name")
            {
                return whoisServers[25, 1];
            }
            else if (tld == "in")
            {
                return whoisServers[26, 1];
            }
            else if (tld == "me")
            {
                return whoisServers[27, 1];
            }
            else if (tld == "at")
            {
                return whoisServers[28, 1];
            }
            else if (tld == "be")
            {
                return whoisServers[29, 1];
            }
            else if (tld == "cn")
            {
                return whoisServers[30, 1];
            }
            else if (tld == "asia")
            {
                return whoisServers[31, 1];
            }
            else if (tld == "ru")
            {
                return whoisServers[32, 1];
            }
            else if (tld == "ro")
            {
                return whoisServers[33, 1];
            }
            else if (tld == "aero")
            {
                return whoisServers[34, 1];
            }
            else if (tld == "fr")
            {
                return whoisServers[35, 1];
            }
            else if (tld == "se")
            {
                return whoisServers[36, 1];
            }
            else if (tld == "nl")
            {
                return whoisServers[37, 1];
            }
            else if (tld == "nz")
            {
                return whoisServers[38, 1];
            }
            else if (tld == "mx")
            {
                return whoisServers[39, 1];
            }
            else if (tld == "tw")
            {
                return whoisServers[40, 1];
            }
            else if (tld == "ch")
            {
                return whoisServers[41, 1];
            }
            else if (tld == "hk")
            {
                return whoisServers[42, 1];
            }
            else if (tld == "ac")
            {
                return whoisServers[43, 1];
            }
            else if (tld == "ae")
            {
                return whoisServers[44, 1];
            }
            else if (tld == "af")
            {
                return whoisServers[45, 1];
            }
            else if (tld == "ag")
            {
                return whoisServers[46, 1];
            }
            else if (tld == "al")
            {
                return whoisServers[47, 1];
            }
            else if (tld == "am")
            {
                return whoisServers[48, 1];
            }
            else if (tld == "as")
            {
                return whoisServers[49, 1];
            }
            else if (tld == "az")
            {
                return whoisServers[50, 1];
            }
            else if (tld == "ba")
            {
                return whoisServers[51, 1];
            }
            else if (tld == "bg")
            {
                return whoisServers[52, 1];
            }
            else if (tld == "bi")
            {
                return whoisServers[53, 1];
            }
            else if (tld == "bj")
            {
                return whoisServers[54, 1];
            }
            else if (tld == "br")
            {
                return whoisServers[55, 1];
            }
            else if (tld == "bt")
            {
                return whoisServers[56, 1];
            }
            else if (tld == "by")
            {
                return whoisServers[57, 1];
            }
            else if (tld == "bz")
            {
                return whoisServers[58, 1];
            }
            else if (tld == "cd")
            {
                return whoisServers[59, 1];
            }
            else if (tld == "ck")
            {
                return whoisServers[60, 1];
            }
            else if (tld == "co")
            {
                return whoisServers[61, 1];
            }
            else if (tld == "cl")
            {
                return whoisServers[62, 1];
            }
            else if (tld == "coop")
            {
                return whoisServers[63, 1];
            }
            else if (tld == "cx")
            {
                return whoisServers[64, 1];
            }
            else if (tld == "cy")
            {
                return whoisServers[65, 1];
            }
            else if (tld == "cz")
            {
                return whoisServers[66, 1];
            }
            else if (tld == "dk")
            {
                return whoisServers[67, 1];
            }
            else if (tld == "dm")
            {
                return whoisServers[68, 1];
            }
            else if (tld == "dz")
            {
                return whoisServers[69, 1];
            }
            else if (tld == "ee")
            {
                return whoisServers[70, 1];
            }
            else if (tld == "eg")
            {
                return whoisServers[71, 1];
            }
            else if (tld == "es")
            {
                return whoisServers[72, 1];
            }
            else if (tld == "fi")
            {
                return whoisServers[73, 1];
            }
            else if (tld == "fo")
            {
                return whoisServers[74, 1];
            }
            else if (tld == "gb")
            {
                return whoisServers[75, 1];
            }
            else if (tld == "ge")
            {
                return whoisServers[76, 1];
            }
            else if (tld == "gl")
            {
                return whoisServers[77, 1];
            }
            else if (tld == "gm")
            {
                return whoisServers[78, 1];
            }
            else if (tld == "gov")
            {
                return whoisServers[79, 1];
            }
            else if (tld == "gr")
            {
                return whoisServers[80, 1];
            }
            else if (tld == "gs")
            {
                return whoisServers[81, 1];
            }
            else if (tld == "hm")
            {
                return whoisServers[82, 1];
            }
            else if (tld == "hn")
            {
                return whoisServers[83, 1];
            }
            else if (tld == "hr")
            {
                return whoisServers[84, 1];
            }
            else if (tld == "hu")
            {
                return whoisServers[85, 1];
            }
            else if (tld == "il")
            {
                return whoisServers[86, 1];
            }
            else if (tld == "int")
            {
                return whoisServers[87, 1];
            }
            else if (tld == "ig")
            {
                return whoisServers[88, 1];
            }
            else if (tld == "ir")
            {
                return whoisServers[89,1];
            }
            else if (tld == "is")
            {
                return whoisServers[90, 1];
            }
            else if (tld == "je")
            {
                return whoisServers[91, 1];
            }
            else if (tld == "jp")
            {
                return whoisServers[92, 1];
            }
            else if (tld == "kg")
            {
                return whoisServers[93, 1];
            }
            else if (tld == "kr")
            {
                return whoisServers[94, 1];
            }
            else if (tld == "la")
            {
                return whoisServers[95, 1];
            }
            else if (tld == "lt")
            {
                return whoisServers[96, 1];
            }
            else if (tld == "lu")
            {
                return whoisServers[97, 1];
            }
            else if (tld == "lv")
            {
                return whoisServers[98, 1];
            }
            else if (tld == "ly")
            {
                return whoisServers[99, 1];
            }
            else if (tld == "ma")
            {
                return whoisServers[100, 1];
            }
            else if (tld == "mc")
            {
                return whoisServers[101, 1];
            }
            else if (tld == "md")
            {
                return whoisServers[102, 1];
            }
            else if (tld == "mil")
            {
                return whoisServers[103, 1];
            }
            else if (tld == "mk")
            {
                return whoisServers[104, 1];
            }
            else if (tld == "ms")
            {
                return whoisServers[105, 1];
            }
            else if (tld == "mt")
            {
                return whoisServers[106, 1];
            }
            else if (tld == "mu")
            {
                return whoisServers[107, 1];
            }
            else if (tld == "my")
            {
                return whoisServers[108, 1];
            }
            else if (tld == "nf")
            {
                return whoisServers[109, 1];
            }
            else if (tld == "pl")
            {
                return whoisServers[110, 1];
            }
            else if (tld == "pr")
            {
                return whoisServers[111, 1];
            }
            else if (tld == "pt")
            {
                return whoisServers[112, 1];
            }
            else if (tld == "sa")
            {
                return whoisServers[113, 1];
            }
            else if (tld == "sb")
            {
                return whoisServers[114, 1];
            }
            else if (tld == "sg")
            {
                return whoisServers[115, 1];
            }
            else if (tld == "sh")
            {
                return whoisServers[116, 1];
            }
            else if (tld == "si")
            {
                return whoisServers[117, 1];
            }
            else if (tld == "sk")
            {
                return whoisServers[118, 1];
            }
            else if (tld == "sm")
            {
                return whoisServers[119, 1];
            }
            else if (tld == "st")
            {
                return whoisServers[120, 1];
            }
            else if (tld == "su")
            {
                return whoisServers[121, 1];
            }
            else if (tld == "tc")
            {
                return whoisServers[122, 1];
            }
            else if (tld == "tf")
            {
                return whoisServers[123, 1];
            }
            else if (tld == "th")
            {
                return whoisServers[124, 1];
            }
            else if (tld == "tj")
            {
                return whoisServers[125, 1];
            }
            else if (tld == "tk")
            {
                return whoisServers[126, 1];
            }
            else if (tld == "tl")
            {
                return whoisServers[127, 1];
            }
            else if (tld == "tm")
            {
                return whoisServers[128, 1];
            }
            else if (tld == "tn")
            {
                return whoisServers[129, 1];
            }
            else if (tld == "to")
            {
                return whoisServers[130, 1];
            }
            else if (tld == "tp")
            {
                return whoisServers[131, 1];
            }
            else if (tld == "tr")
            {
                return whoisServers[132, 1];
            }
            else if (tld == "ua")
            {
                return whoisServers[133, 1];
            }
            else if (tld == "uy")
            {
                return whoisServers[134, 1];
            }
            else if (tld == "uz")
            {
                return whoisServers[135, 1];
            }
            else if (tld == "va")
            {
                return whoisServers[136, 1];
            }
            else if (tld == "vc")
            {
                return whoisServers[137, 1];
            }
            else if (tld == "ve")
            {
                return whoisServers[138, 1];
            }
            else if (tld == "vg")
            {
                return whoisServers[139, 1];
            }
            else if (tld == "yu")
            {
                return whoisServers[140, 1];
            }
            else if (tld == "science")
            {
                return whoisServers[141, 1];
            }
            else if (tld == "xyz")
            {
                return whoisServers[142, 1];
            }
            else
            {
                return whoisServers[0, 1];
            }
        }

        public string query(string domain)
        {
            try
            {
                string domainname = GetDomainName(domain);
                string whoisserver = getWhoisServer(GetDomainTld(domain));
                TcpClient TCPC = new TcpClient(whoisserver, 43);
                string strDomain = domainname + "\r\n";
                byte[] arrDomain = Encoding.ASCII.GetBytes(strDomain);
                Stream objStream = TCPC.GetStream();
                objStream.Write(arrDomain, 0, strDomain.Length);
                StreamReader objSR = new StreamReader(TCPC.GetStream(), Encoding.ASCII);
                string icerik = Regex.Replace(objSR.ReadToEnd(), "\n", "<br>");
                TCPC.Close();
                return icerik;
            }
            catch(Exception ex)
            {
                return ex.ToString();
            }
        }
    }
}
