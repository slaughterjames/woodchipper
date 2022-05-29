# woodchipper

Meant to work in tandem with Static, analyzes downloaded e-mail samples from VirusTotal.

*File: 02d95abc9b3ddd239a6b528c9e22bc31f27fb730bbfc5892d0339bf771c523e2.eml*\
*Size Of File: 927084 bytes.*\
*SHA256: 02d95abc9b3ddd239a6b528c9e22bc31f27fb730bbfc5892d0339bf771c523e2*\
*FileType: RFC 822 mail, ASCII text, with very long lines, with CRLF line terminators\n'*\
*Message Date: Thu, 26 May 2022 06:27:19 +0200*\
*Message To: Johnson& Johnson Consumer- Egypt <MSalem4@mz2.emoxi.sbs>*\
*Message From: Mohammed Salem <MSalem4@mz2.emoxi.sbs>*\
*Message Subject: Re: Action Required - Johnson& Johnson -PO- 216238068*\
*Attachment: Urgent_Order.gz*\
*Attachment: |--------> 2 total attachments failed to be extracted...*\
*VirusTotal suggested threat label: trojan.msil/mail*\
*VirusTotal Suspicious: 0*\
*VirusTotal Malicious: 16*\

Usage: [required] --dir [optional] --output --debug --help\
Example: ./woodchipper.py --dir 20220209/gov_emails --output 20220209-gov_emails.txt --debug\
Required Arguments:\
--dir - directory to start parsing\
Optional Arguments:\
--output - location of the output file\\
--debug - Prints verbose logging to the screen to troubleshoot issues with a recon installation.\
--help - You're looking at it!\
