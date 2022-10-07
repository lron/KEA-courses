# Applied Cryptography resources

## Contents

- [Introduction and classical crypto](#introduction-and-classical-crypto)
- [Frequency analysis](#frequency-analysis)
- [OTP](#otp)
- [Block ciphers](#block-ciphers)
- [Modes of operation](#modes-of-operation)
- [Padding oracle attacks](#padding-oracle-attacks)
- [RC4](#rc4)
- [WiFi encryption](#wifi-encryption)
- [Storage encryption](#storage-encryption)
- [RSA](#rsa)
- [Libsodium crypto library](#libsodium-crypto-library)
- [Quantum cryptography](#quantum-cryptography)
- [Key exchange](#key-exchange)
- [Logjam attack](#logjam-attack)
- [Ransomware](#ransomware)
- [Hashing](#hashing)
- [Password security](#password-security)
- [ECDSA signature](#ecdsa-signature)
- [Sign+encrypt](#signencrypt)
- [Cryptographically secure randomness](#cryptographically-secure-randomness)
- [PGP](#pgp)
- [JWT](#jwt)
- [Certificates](#certificates)
- [TLS](#tls)
- [Secret sharing](#secret-sharing)
- [Secure chats](#secure-chats)
- [Books available online](#books-available-online)
- [Links on crypto in general](#links-on-crypto-in-general)
- [Crypto challenges](#crypto-challenges)

## Introduction and classical crypto

- [Schneier's Law - Schneier on Security](https://www.schneier.com/blog/archives/2011/04/schneiers_law.html) - Article discussing those situations in which people believe they've created something secure, overlooking some obvious faults.
- [Stack Overflow Considered Harmful? The Impact of Copy&Paste on Android Application Security | IEEE Conference Publication](https://ieeexplore.ieee.org/document/7958574) - Paper quantifying the proliferation of security-related code snippets from Stack Overflow in Android applications.
- [Welcome to pycipher’s documentation! — pycipher 1 documentation](https://pycipher.readthedocs.io/en/master/#caesar-cipher) - Python library implementing Caesar and other classical crypto ciphers.
- [Caesar cipher - Rosetta Code](https://rosettacode.org/wiki/Caesar_cipher) - Yet another implementation of Caesar cipher.
- [Cracking Enigma in 2021 - Computerphile - YouTube](https://www.youtube.com/watch?v=RzWB5jL5RX0) - Approx. 21min video explaining how surprisingly difficult it would still be to crack Enigma with today's computer power.
- [WWII Enigma Machine: The Enigma Project - YouTube](https://www.youtube.com/watch?v=elYw4Ve4F-I) - Approx. 5min video showing how the Enigma machine looks and works.
- [Cracking the NAZI Enigma Code Machine - YouTube](https://www.youtube.com/watch?v=Hb44bGY2KdU) - Approx. 9min video showing how the Enigma machine was cracked.

## Frequency analysis

- [Frequency Analysis: Breaking the Code](http://crypto.interactive-maths.com/frequency-analysis-breaking-the-code.html) - Provides a very good explanation, together with examples, of frequency analysis.
- [Frequency Analysis Tool](https://www.dcode.fr/frequency-analysis) - Tools for frequency analysis, a cryptanalysis method studying the frequency of letters or groups of characters in a ciphered message.

## OTP

- [One-Time Pads – Cryptosmith](https://cryptosmith.com/2007/06/09/one-time-pads/) - Very good explanation of OTP and why they are impractical.
- [Is OTP useful in modern electronic communication? - Cryptography Stack Exchange](https://crypto.stackexchange.com/a/11205) - Talks about problems of OTP.
- [The one-time pad (video) | Cryptography | Khan Academy](https://www.khanacademy.org/computing/computer-science/cryptography/crypt/v/one-time-pad) - Approx. 3min video explanation of OTP.
- [One Time Pad FAQ](http://www.ranum.com/security/computer_security/papers/otp-faq/index.htm) - Questiions and answers about OTP, especially interesting is the discussion about what can be used as a pad.
- [Travis Dazell: Many Time Pad Attack - Crib Drag](http://travisdazell.blogspot.com/2012/11/many-time-pad-attack-crib-drag.html) - This tutorial shows what happens when you re-use a key to encrypt more than one message in OTP and also shows how to uncover the plaintext of two messages that have been encrypted with the same key, without even knowing the key.
- [Bruce Schneier’s List of Snake Oil Warning Signs – Internet Salmagundi](https://internet-salmagundi.com/2020/05/bruce-schneiers-list-of-snake-oil-warning-signs/) - Typical expressions and terms used for false claims about security.

## Block ciphers

- [Ch4 of the book Serious Cryptography](https://nostarch.com/download/SeriousCryptography_Chapter4_sample.pdf) - Free chapter on Block Ciphers.
- [Using padding in encryption](https://www.di-mgt.com.au/cryptopad.html) - Explains the different padding mechanisms that can be used in block ciphers.
- [A Stick Figure Guide to the Advanced Encryption Standard (AES)](http://www.moserware.com/2009/09/stick-figure-guide-to-advanced.html) - The famous comic strip explaining the history of AES.
- [AES Rijndael Cipher - Visualization - YouTube](https://www.youtube.com/watch?v=mlzxpkdXP58) - Approx. 3min video. With a few errors, though, but gives a good general idea on how AES works.
- [Ch6 of the (free) book "Crypto 101"](https://www.crypto101.io/Crypto101.pdf) - See pp41-44 for DES and 3DES.
- [Modes of Operation - Computerphile - YouTube](https://www.youtube.com/watch?v=Rk0NIQfEXBA) - Approx. 14min video about ECB, CBC and CTR.
- [How secure is 256 bit security? - YouTube](https://www.youtube.com/watch?v=S9JGmA5_unY) - How hard is it to find a 256-bit hash just by guessing and checking? 5min video comparing the difficulty of such a guess with elements in the universe.

## Modes of operation

- [How to choose an Authenticated Encryption mode – A Few Thoughts on Cryptographic Engineering](https://blog.cryptographyengineering.com/2012/05/19/how-to-choose-authenticated-encryption/) - From Matthew Green's blog. Focuses on authenticated encryption (encryption that ensures integrity and confidentiality at the same time).
- [Zoom’s Flawed Encryption Linked to China](https://theintercept.com/2020/04/03/zooms-encryption-is-not-suited-for-secrets-and-has-surprising-links-to-china-researchers-discover/) - Article talking about the (weak) encryption that Zoom was using back in 2020.
- [Zoom Finally Takes Encryption Seriously: And Goes All GCM | by Prof Bill Buchanan OBE | ASecuritySite: When Bob Met Alice | Medium](https://medium.com/asecuritysite-when-bob-met-alice/zoom-finally-takes-encryption-seriously-and-goes-all-gcm-2e1203a7274b) - Explains the improvements made to Zoom encryption and the aspects that still need to be improved.
- [Zoom encryption whitepaper](https://www.usm.edu/itech/_files/zoom_encryption_whitepaper.pdf) - This whitepaper shows the weak encryption Zoom was using in 2020.
- [How to choose an AES encryption mode (CBC ECB CTR OCB CFB)? - Stack Overflow](https://stackoverflow.com/questions/1220751/how-to-choose-an-aes-encryption-mode-cbc-ecb-ctr-ocb-cfb/42658861#42658861) - Interesting Stack Overflow thread about which mode of operation to go for, depending on the situation. Current recommendations are in favour of AES-GCM.
- [GitHub - robertdavidgraham/ecb-penguin: ECB penguin](https://github.com/robertdavidgraham/ecb-penguin) - Demons of the famous ECB penguin using Openssl.

## Padding oracle attacks

- [Cryptography - Padding Oracle Attacks - YouTube](https://www.youtube.com/watch?v=aH4DENMN_O4) - Approx. 17min video explaining an attack that takes advantage of the error messages received from a web server when decrypting a ciphertext that contains padding.
- [CBC Padding Oracle Attacks Simplified – Key concepts and pitfalls | The Grymoire](https://grymoire.wordpress.com/2014/12/05/cbc-padding-oracle-attacks-simplified-key-concepts-and-pitfalls/) - Padding oracle attack explained in a simpler way.

## RC4

- [The Misuse of RC4 in Microsoft Word and Excel (scientific paper)](https://eprint.iacr.org/2005/007.pdf) - Paper from 2005 pointing out at a security flaw that Microsoft Word and Excel had regarding their use of RC4 cipher.
- [Fluhrer, Mantin and Shamir attack - Wikipedia](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack) - Attack to RC4 cipher used in WEP encryption of WiFi networks.

## WiFi encryption

- [Key Reinstallation Attacks: Forcing Nonce Reuse in WPA2 (scientific paper)](https://papers.mathyvanhoef.com/ccs2017.pdf) - Attack on WPA2, abusing design or implementation flaws in cryptographic protocols to reinstall an already-in-use key.

## Storage encryption

- [Google Online Security Blog: Introducing Adiantum: Encryption for the Next Billion Users](https://security.googleblog.com/2019/02/introducing-adiantum-encryption-for.html) - Article discussing disk and file encryption and why they are specially challenging when compared to in-transit encryption.

## RSA

- [Why some cryptographic keys are much smaller than others](https://blog.cloudflare.com/why-are-some-keys-small/) - Comparison of key lengths in symmetric and asymmetric encryption and why they are so different.
- [Millions of high-security crypto keys crippled by newly discovered flaw | Ars Technica](https://arstechnica.com/information-technology/2017/10/crypto-failure-cripples-millions-of-high-security-keys-750k-estonian-ids/) - Factorization weakness lets attackers impersonate key holders and decrypt their data.
- [Security Flaw in Infineon Smart Cards and TPMs - Schneier on Security](https://www.schneier.com/blog/archives/2017/10/security_flaw_i_1.html) -  The flaw allowed an attacker to recover private keys from the public keys.
- [Understanding Cryptography with RSA | by Ryan Canty | Medium](https://medium.com/@jryancanty/understanding-cryptography-with-rsa-74721350331f) - Easy-to-understand mathematical explanation of RSA.
- [The Full Story of the Stunning RSA Hack Can Finally Be Told | WIRED](https://www.wired.com/story/the-full-story-of-the-stunning-rsa-hack-can-finally-be-told/) - The article explains how Chinese spies stole the crown jewels of cybersecurity—stripping protections from firms and government agencies worldwide in 2011.
- [RSA: Over 40 Years Old and Still Amazing! — Let’s Crack It | by Prof Bill Buchanan OBE | Medium](https://medium.com/asecuritysite-when-bob-met-alice/rsa-over-40-years-old-and-still-amazing-lets-crack-it-6eaf279326c3) - Explains how to solve some RSA challenges.

## Libsodium crypto library

- [Timing attacks and usernames - Brendan Long](https://www.brendanlong.com/timing-attacks-and-usernames.html) - Timing attacks in authentication, to better understand the concept of the attack itself, which can then be applied to cryptography.
- [How to Safely Implement Cryptography Features in Any Application](https://paragonie.com/blog/2015/09/how-to-safely-implement-cryptography-in-any-application) - Exposes reasons to use Libsodium cryptographic library instead of other libraries like Mcrypt, Openssl, Bouncy Castle or KeyCZar.
- [Introducing Sodium, a new Cryptographic Library](https://umbrella.cisco.com/blog/announcing-sodium-a-new-cryptographic-library) -  No matter how secure a function is, its security can be totally destroyed by a tiny weakness in its implementation or by using it incorrectly. Libsodium helps preventing this.
- [Crypto is Broken or How to Apply Secure Crypto as a Developer - codecentric AG Blog](https://blog.codecentric.de/en/2014/03/crypto-broken-apply-secure-crypto-developer/) - This article shows how difficult it is to get crypto right, even if you have the best intentions. It is insufficient to just use the right libraries. NaCl and Libsodium offer a simple way to avoid knowing all the nasty details while providing strong crypto.
- [Installation — PyNaCl documentation](https://pynacl.readthedocs.io/en/latest/install/) - One of the existing Python wrappers for Libsodium library.

## Quantum cryptography

- [NIST's pleasant post-quantum surprise](https://blog.cloudflare.com/nist-post-quantum-surprise/) - Very nice long article presenting the post-quantum cryptography algorithms that will be standardized by NIST, as a result of the third round in the contest.
- [Post-Quantum Cryptography | CSRC](https://csrc.nist.gov/projects/post-quantum-cryptography) - NIST initiated a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms.
- [Post-Quantum Cryptography: Q&A with Jean-Philippe Aumasson](https://www.infoq.com/news/2021/04/post-quantum-crypto-aumasson-qa/) - Interesting interview to cryptography researcher Jean-Philippe Aumasson to understand where post-quantum crypto is headed.
- [Will Quantum Computers break encryption? - YouTube](https://www.youtube.com/watch?v=6H_9l9N3IXU&t=776s) - Approx. 15min video. Very interesting and easy to understand.
- [Quantum Computing and Post-Quantum Cryptography](https://media.defense.gov/2021/Aug/04/2002821837/-1/-1/1/Quantum_FAQs_20210804.PDF) - FAQ by NSA. From Aug.2021.
- [Understanding and explaining post-quantum crypto with cartoons](https://www.rsaconference.com/Library/presentation/USA/2020/understanding-and-explaining-post-quantum-crypto-with-cartoons) - Explains how post-quantum cryptography works with a 100 percent cartoon-based slide show. All cartoon stories presented refer to easy-to-understand analogies. No advanced mathematical skills are required.
- [GitHub - veorq/awesome-post-quantum](https://github.com/veorq/awesome-post-quantum) - A curated list of resources about post-quantum cryptography.

## Key exchange

- [Is there any particular reason to use Diffie-Hellman over RSA for key exchange? - Stack Exchange](https://security.stackexchange.com/questions/35471/is-there-any-particular-reason-to-use-diffie-hellman-over-rsa-for-key-exchange#:~:text=That%20part%20is%20about%20reducing,for%20DH%20than%20for%20RSA.) - Compares the RSA-based key exchange and Diffi-Hellman key exchange methods.

## Logjam attack

- [Weak Diffie-Hellman and the Logjam Attack](https://weakdh.org/) - Official website of the attack.
- [LogJam Attack Explained. To understand DH key exchange, let’s… | by c0D3M | Medium](https://medium.com/@c0D3M/logjam-attack-explained-829d62d951a6)
- [cryptography - "Diffie-Hellman Key Exchange" in plain English - Stack Exchange](https://security.stackexchange.com/questions/45963/diffie-hellman-key-exchange-in-plain-english)
- [J. Alex Halderman, Nadia Heninger: Logjam: Diffie-Hellman, discrete logs, the NSA, and you - YouTube](https://youtu.be/mS8gm-_rJgM) - Approx. 1h video. Most presentations from Alex Halderman are very entertaining.

## Ransomware

- [Ransomware encryption techniques | by Tarcísio Marinho | Medium](https://medium.com/@tarcisioma/ransomware-encryption-techniques-696531d07bb9)
- [REvil Revealed - Tracking a Ransomware Negotiation and Payment](https://www.elliptic.co/blog/revil-revealed-tracking-ransomware-negotiation-and-payment)
- [Ransomware’s Dangerous New Trick Is Double-Encrypting Your Data | WIRED](https://www.wired.com/story/ransomware-double-encryption/)
- [Ransomware: how an attack works](https://support.sophos.com/support/s/article/KB-000036277?language=en_US)
- [Disrupting Ransomware by Disrupting Bitcoin - Schneier on Security](https://www.schneier.com/blog/archives/2021/07/disrupting-ransomware-by-disrupting-bitcoin.html) - Suggests possible ways of making ransomware not a viable business.
- [Insurance and Ransomware - Schneier on Security](https://www.schneier.com/blog/archives/2021/07/insurance-and-ransomware.html) - Article blaming the cyber-insurance companies of the ransom being paid.
- [Details of the REvil Ransomware Attack - Schneier on Security](https://www.schneier.com/blog/archives/2021/07/details-of-the-revil-ransomware-attack.html)
- [Ransomware Profitability - Schneier on Security](https://www.schneier.com/blog/archives/2021/02/ransomware-profitability.html) - Ransomware is the most profitable cybercrime business model nowadays.
- [The No More Ransom Project](https://www.nomoreransom.org/en/decryption-tools.html)
- [Combating Ransomware - report from Institute for Security + Technology](https://securityandtechnology.org/wp-content/uploads/2021/04/IST-Ransomware-Task-Force-Report.pdf)
- [How does a computer become infected with ransomware? - YouTube](https://youtu.be/v-ITcpD1KcQ) - 1min video showing a ransomware attack in action.
- [Leakware-Ransomware-Hybrid Attacks - Hornetsecurity](https://www.hornetsecurity.com/en/security-informationen-en/leakware-ransomware-hybrid-attacks/)
- [LockFile Ransomware Uses Unique Methods to Avoid Detection | eSecurityPlanet](https://www.esecurityplanet.com/threats/lockfile-ransomware-evasion-rechniques/)

## Hashing

- [DFIR\_Resources\_REvil\_Kaseya/Hashes.txt at main · cado-security/DFIR\_Resources\_REvil\_Kaseya · GitHub](https://github.com/cado-security/DFIR_Resources_REvil_Kaseya/blob/main/IOCs/Hashes.txt)
- [An Illustrated Guide to Cryptographic Hashes](http://www.unixwiz.net/techtips/iguide-crypto-hashes.html) - A bit outdated but good intro to hash functions.
- [MD5 Collisions, visualized](https://www.links.org/?p=6)
- [Colliding X.509 Certificates based on MD5-collisions](https://www.win.tue.nl/~bdeweger/CollidingCertificates/)
- [How to choose the right parameters for Argon2?](https://www.twelve21.io/how-to-choose-the-right-parameters-for-argon2/)
- [Malicious SHA-1](https://malicioussha1.github.io/#downloads)
- [Rainbow tables explained: How they work and why they're (mostly) obsolete | CSO Online](https://www.csoonline.com/article/3623195/rainbow-tables-explained-how-they-work-and-why-theyre-mostly-obsolete.html)

## Password security

- [NIST Digital Identity Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63-3.pdf) - From June 2017.
- [Changes in Password Best Practices - Schneier on Security](https://www.schneier.com/blog/archives/2017/10/changes_in_pass.html)
- [OWASP's Password Storage cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [YouTube - How NOT to Store Passwords! by Computerphile](https://www.youtube.com/watch?v=8ZtInClXe1Q) - Approx. 9min video.
- [Password security: past, present, future (Passwords^12, PHDays 2012)](https://www.openwall.com/presentations/Passwords12-The-Future-Of-Hashing/)
- [OWASP Threat model for secure password storage](https://owasp.org/www-pdf-archive//Secure_Password_Storage.pdf)
- [Response UX response times](https://www.nngroup.com/articles/response-times-3-important-limits/) - Useful to follow when designing login systems where passwords are stored using KDFs.
- [Have I Been Pwned: API v3](https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange)

## ECDSA signature

- [CVE-2022-21449: Psychic Signatures in Java – Neil Madden](https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/)
- [Not Playing Randomly: The Sony PS3 and Bitcoin Crypto Hacks | by Prof Bill Buchanan OBE | Medium](https://medium.com/asecuritysite-when-bob-met-alice/not-playing-randomly-the-sony-ps3-and-bitcoin-crypto-hacks-c1fe92bea9bc)
- [Recovering The Private Key in a ECDSA Signature Using A Single Random Nonce | by Prof Bill Buchanan OBE | ASecuritySite: When Bob Met Alice | Medium](https://medium.com/asecuritysite-when-bob-met-alice/cracking-ecdsa-with-a-leak-of-the-random-nonce-d72c67f201cd)

## Sign+encrypt

- [Which one is more preferable, encrypt-then-sign or sign-then-encrypt? - Quora](https://www.quora.com/Which-one-is-more-preferable-encrypt-then-sign-or-sign-then-encrypt?share=1) - It's not the same to encrypt and then sign, than signing and then encrypting it.

## Cryptographically secure randomness

- [Myths about /dev/urandom \[Thomas Hühn\]](https://www.2uo.de/myths-about-urandom/)
- [A Critical Random Number Generator Flaw Affects Billions of IoT Devices](https://thehackernews.com/2021/08/a-critical-random-number-generator-flaw.html)

## PGP

- [PGP key operations](https://www.ws.afnog.org/afnog2014/cte/tuesday/pgp-handson.pdf)
- [Decade-old Efail flaws can leak plaintext of PGP- and S/MIME-encrypted emails | Ars Technica](https://arstechnica.com/information-technology/2018/05/decade-old-efail-attack-can-decrypt-previously-obtained-encrypted-e-mails/)
- [EFAIL bug on PGP](https://efail.de/)
- [StackExchange/blackbox](https://github.com/StackExchange/blackbox) - Safely store and encrypt secrets in Git/Mercurial/Subversion using GPG.
- [Git-secret.io](https://git-secret.io/) - Encrypts files in your git repository using GPG.

## JWT

- [Public Claims and How to validate a JWT](https://medium.com/dataseries/public-claims-and-how-to-validate-a-jwt-1d6c81823826)
- [jwt.io/](https://jwt.io/) - Allows to validate certain JWT.
- [GitHub - foundersandcoders/ws-jwt-stateless-session: Week 7 - Session Management Workshop](https://github.com/foundersandcoders/ws-jwt-stateless-session)

## Certificates

- [Understanding TLS Certificates. A Quick Introduction to TLS… | by Ravi | Demystifying Security | Medium](https://medium.com/demystifying-security/understanding-tls-certificates-76bdd5815d95)
- [Your Guide to X509 Certificates (For Mortals)](https://adamtheautomator.com/x509-certificates/)
- [PEM, DER, CRT, and CER: X.509 Encodings and Conversions](https://www.ssl.com/guide/pem-der-crt-and-cer-x-509-encodings-and-conversions/)

## TLS

- [Final Report on DigiNotar Hack Shows Total Compromise of CA Servers | Threatpost](https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/)
- [TLS 1.3: Everything you need to know - Security Boulevard](https://securityboulevard.com/2019/07/tls-1-3-everything-you-need-to-know/)
- [The new illustrated TLS connection](https://tls13.ulfheim.net/) - Excellent detailed explanation of every field involved in the TLS v1.3 handshaking process.
- [The TLS Handshake: Taking a closer look - Hashed Out by The SSL Store™](https://www.thesslstore.com/blog/explaining-ssl-handshake/)
- [Browsers to block access to HTTPS sites using TLS 1.0 and 1.1 starting this month | ZDNet](https://www.zdnet.com/article/browsers-to-block-access-to-https-sites-using-tls-1-0-and-1-1-starting-this-month/)
- [Cipher Suites: Ciphers, Algorithms and Negotiating Security Settings](https://www.thesslstore.com/blog/cipher-suites-algorithms-security-settings/)
- [Transport Layer Protection · OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [OpenSSL Cookbook: Chapter 2. Testing with OpenSSL](https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html)
- [Decrypting SSL/TLS traffic with Wireshark](https://resources.infosecinstitute.com/topic/decrypting-ssl-tls-traffic-with-wireshark/) - Only works for TLS v1.2.
- [Wireshark 2 og HTTPS - Københavns Erhvervsakademi](https://kea.dk/e-learning/wireshark-2) - Video made by Dany Kallas, explaining how to do it, but again it only works with TLS v1.2 and not TLS v.1.3. The main reason is that the video assumes the use of RSA key exchange method which TLS v1.3 doesn’t support anymore (because RSA doesn’t provide forward secrecy), only Diffie-Hellman key exchange.
- [Debugging TLS issues with Wireshark - from SharkFest'19](https://lekensteyn.nl/files/wireshark-tls-debugging-sharkfest19us.pdf) - Decryption of TLS v1.3 with Wireshark. These are the slides of the presentation. Note: I still myself haven’t tried it yet but you’re more than welcome to try, see if it works and if so, let me know! ;)
- [TLS deployment best practices](https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices)
- [Man-in-the-Middle TLS Protocol Downgrade Attack | Praetorian](https://www.praetorian.com/blog/man-in-the-middle-tls-ssl-protocol-downgrade-attack)
- [LogJam TLS vulnerablity - YouTube](https://www.youtube.com/watch?v=87s1nkATfzk) - Approx. 1min video.
- [Downgrade attack on TLS 1.3 and vulnerabilities in major TLS libraries](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2019/february/downgrade-attack-on-tls-1.3-and-vulnerabilities-in-major-tls-libraries/)
- [How does TLS 1.3 protect against downgrade attacks? | The blog of a gypsy engineer](https://blog.gypsyengineer.com/en/security/how-does-tls-1-3-protect-against-downgrade-attacks.html)
- [Heartbleed Bug (official website)](https://heartbleed.com/)
- [RFC 7457 - Summarizing Known Attacks on Transport Layer Security (TLS) and Datagram TLS (DTLS)](https://datatracker.ietf.org/doc/html/rfc7457)
- [What's the difference between end-to-end and regular TLS encryption? - Information Security Stack Exchange](https://security.stackexchange.com/questions/157292/whats-the-difference-between-end-to-end-and-regular-tls-encryption) - Yes, strictly speaking TLS doesn't provide end-to-end encryption.

## Secret sharing

- [Are there any "real world" implementations of secret-sharing encryption schemes? - Stack Exchange](https://security.stackexchange.com/questions/5410/are-there-any-real-world-implementations-of-secret-sharing-encryption-schemes)
- [Shamir's Secret Sharing Step-By-Step - Qvault](https://qvault.io/2020/08/18/very-basic-shamirs-secret-sharing/)
- [DNSSEC Root Key Split Among Seven People - Schneier on Security](https://www.schneier.com/blog/archives/2010/07/dnssec_root_key.html)
- [An Order of Seven Global Cyber-Guardians Now Hold Keys to the Internet](https://www.popsci.com/technology/article/2010-07/order-seven-cyber-guardians-around-world-now-hold-keys-internet/)
- [Shamir's Secret Sharing Shortcomings](https://blog.keys.casa/shamirs-secret-sharing-security-shortcomings/) - Interesting article that points at some of the reasons why the concept, despite sounding revolutionary, is not in practice used more often.

## Secure chats

- [Double Ratchet Messaging Encryption - Computerphile - YouTube](https://www.youtube.com/watch?v=9sO2qdTci-s)

## Books available online

- [Crypto 101](https://www.crypto101.io/Crypto101.pdf)
- [Handbook of Applied Cryptography](http://cacr.uwaterloo.ca/hac/)
- [Security Engineering - Dependable Distributed Systems (free 3rd edition)](http://www.cl.cam.ac.uk/~rja14/book.html) - The book has a few chapters devoted to cryptography.

## Links on crypto in general

- [CyberChef](https://gchq.github.io/CyberChef/) - This tool is known as the cyber Swiss army knife of cryptography.
- [sobolevn/awesome-cryptography](https://github.com/sobolevn/awesome-cryptography) - A curated list of cryptography resources and links about cryptography.
- [Next Generation Cryptography by CISCO](https://tools.cisco.com/security/center/resources/next_generation_cryptography) - Crypto recommendations, Oct. 2000.
- [Cryptography is not Magic](https://loup-vaillant.fr/articles/crypto-is-not-magic)
- [CryptoGotchas](https://github.com/SalusaSecondus/CryptoGotchas/blob/master/README.md) - List of counter-intuitive "gotchas" in cryptography. Very interesting to read as a wrap-up of the whole course.
- [Ciphey/Ciphey: automatic decryption tool + deep neural networks](https://github.com/Ciphey/Ciphey)- Automatically decrypt encryptions without knowing the key or cipher, decode encodings, and crack hashes.
- [Send og modtag sikker e-mail - NemID](https://www.nemid.nu/dk-da/kom_i_gang_med_nemid/sikker_e-mail/send_og_modtag_sikker_e-mail/) - In Danish. Explains how to use NemId to send encrypted emails.
- [CrypTool](https://www.cryptool.org/en/) - Very interesting portal with cryptography programs, resources and tools.
- [Schneier on Security: Crypto-gram newsletter](https://www.schneier.com/crypto-gram/) - Very interesting cryptography newsletter good to be subscribed to.
- [Cryptii](https://cryptii.com/) - Web app offering modular conversion, encoding and encryption online.

## Crypto challenges

- [CryptoHack](https://cryptohack.org/) - A fun, free platform for learning modern cryptography.
- [SpiderLabs/CryptOMG](https://github.com/SpiderLabs/CryptOMG) - Configurable CTF style test bed that highlights common flaws in cryptographic implementations. 
- [GitHub - c4pr1c3/docker-cryptomg: CryptOMG is a configurable CTF style test bed that highlights common flaws in cryptographic implementations.](https://github.com/c4pr1c3/docker-cryptomg) - Instructions on how to run CryptOMG using Docker.
- [The Cryptopals Crypto Challenges](https://cryptopals.com/) - By NCC Group.
- [Id0-rsa.pub](https://id0-rsa.pub/) - Problems related to poorly implemented security.