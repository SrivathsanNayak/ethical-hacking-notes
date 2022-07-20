# MAL: REMnux - The Redux - Easy

1. [Analysing Malicious PDF's](#analysing-malicious-pdfs)
2. [Analysing Malicious Microsoft Office Macros](#analysing-malicious-microsoft-office-macros)
3. [I Hope you Packed your Bags](#i-hope-you-packed-your-bags)

## Analysing Malicious PDF's

* We can use ```peepdf``` for a precursory analysis of a PDF file to determine the presence of JavaScript; we can extract the JS code without executing it.

```shell
peepdf notsuspicious.pdf
#OpenAction executes the code when PDF is launched

#setup script file for peepdf
#extract js and pipe contents into another pdf
echo 'extract js > js-from-notsuspicious.pdf' > extracted_js.txt

#peepdf uses the script and the pdf for extraction
peepdf -s extracted_js.txt notsuspicious.pdf

#view extracted js
cat js-from-notsuspicious.pdf

#we can follow the same procedure for advert.pdf
```

```markdown
1. How many types of categories of "Suspicious elements" are there in "notsuspicious.pdf" - 3

2. Use peepdf to extract the javascript from "notsuspicious.pdf". What is the flag? - THM{Luckily_This_Isn't_Harmful}

3. How many types of categories of "Suspicious elements" are there in "advert.pdf" - 6

4. Now use peepdf to extract the javascript from "advert.pdf". What is the value of "cName"? - notsuspicious
```

## Analysing Malicious Microsoft Office Macros

* ```vmonkey``` is a parser engine capable of analysing visual basic macros without executing/opening the document.

```shell
vmonkey DefinitelyALegitInvoice.doc

vmonkey Taxes2020.doc
```

```markdown
1. What is the name of the Macro for "DefinitelyALegitInvoice.doc" - DefoLegit

2. What is the URL the Macro in "Taxes2020.doc" would try to launch? - http://tryhackme.com/notac2cserver.sh
```

## I Hope you Packed your Bags

* File entropy is a rating that scores how random the data within a PE (portable executable) file is; higher the entropy, higher the randomness.

* File entropy is very indicative of the suspiciousness of a file as malware authors use techniques like encryption or packing for code obfuscation, thus increasing entropy.

```markdown
1. What is the highest file entropy a file can have? - 8

2. What is the lowest file entropy a file can have? - 0

3. Name a common packer that can be used for applications? - UPX
```

* We can use ```volatility``` to understand memory dumps.

```shell
volatility -f Win7-Jigsaw.raw imageinfo

volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 pslist

#analyze dlls
volatility -f Win7-Jigsaw.raw --profile=Win7SP1x64 dlllist -p 3704
```
