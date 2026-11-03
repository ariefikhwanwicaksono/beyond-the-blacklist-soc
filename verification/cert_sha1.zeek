# Print SHA-1, SHA-256 and subject of every distinct X.509 certificate seen in a pcap.
# Zeek's x509.log fingerprints are SHA-256, but abuse.ch SSLBL lists SHA-1, so the DER is hashed here.
# Usage: zeek -C -r dridex.pcap cert_sha1.zeek > certs.tsv
global seen: set[string];

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
	{
	local der = x509_get_certificate_string(cert_ref);
	local h = sha1_hash(der);
	if ( h in seen )
		return;
	add seen[h];
	print fmt("%s|%s|%s", h, sha256_hash(der), cert$subject);
	}
