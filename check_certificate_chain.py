#!/usr/bin/env python
#
# check_certificate_chain.py:
# does exactly what the name suggests.
#
# X.509 sucks!
#
# AUTHORS:
#   Aaron <azet@azet.org> Zauner
#
# LICENSE:
#   MIT License
#
# TODO: 
# - Add interface to certificate-transparency.
# - Check/Verify certificates.
#
import sys
import M2Crypto.SSL

def main():
    server  = str(sys.argv[1])
    port    = int(sys.argv[2])
    
    tls_context = M2Crypto.SSL.Context();
    # we want to check unknown CAs as well
    tls_context.set_allow_unknown_ca(True)
    # sadly, certificate verification almost always fails.
    tls_context.set_verify(M2Crypto.SSL.verify_none, False)
 
    conn = M2Crypto.SSL.Connection(tls_context)
    conn.connect((server, port))
 
    chain = conn.get_peer_cert_chain()

    print "\n>> Certificate Chain:\n"
    i = 0
    for cert in reversed(chain):
        i += 1
        print " [+] " + "*"*i + "\t\t%s" % cert.get_subject().as_text()

    print "\n>> Certificate Information:\n"
    for cert in reversed(chain):
        pkey = cert.get_pubkey()
        print "." * 80
        print "- [Subject]:\t\t%s"          % cert.get_subject().as_text()
        print "- [Issuer]:\t\t%s"           % cert.get_issuer().as_text()
        print "- [Valid from]:\t\t%s"       % cert.get_not_before()
        print "- [Valid until]:\t%s"        % cert.get_not_after()
        if cert.check_ca():
            print "- [Authority]:\t\tIs a CA"
        else:
            print "- [Authority]:\t\tIs not a CA"
        print "- [Version]:\t\t%s"          % cert.get_version()
        print "- [Serial No.]:\t\t%s"       % cert.get_serial_number()
        print "- [X.509 Extension Details]:"
        for k in range(0, cert.get_ext_count()):
            ext = cert.get_ext_at(k)
            print "  `-- [x509_" + ext.get_name() + "]:\n\t   %s\n" % ext.get_value().replace('\n', ' ')
        print "- [Fingerprint]:\t(hex) %s"  % cert.get_fingerprint()
        print "- [Keysize]:\t\t%s Bits"     % (pkey.size() * 8)
        print "- [RSA Modulus]:\t(hex) %s"  % pkey.get_modulus()
        print "- [RSA Key]:\n%s"            % pkey.get_rsa().as_pem()

if __name__ == '__main__':
    if len(sys.argv) <= 2:
       print "  Usage:\n\tcheck_certificate_chain.py [server/ip] [port]\n"
       exit(1)

    main()

