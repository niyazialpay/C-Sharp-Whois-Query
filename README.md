# C# Whois Query
You can query for whois with this file.

#How to usage

Open a new form window and add a webBrowser, textBox and button component. Add the following code to the button click event.


whois whois = new whois();

webBrowser1.DocumentText = whois.query(textBox1.Text);
