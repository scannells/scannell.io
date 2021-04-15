+++
title = "Findings"
description = "An incomplete list of all vulnerabilities I ever found in software"
date = "2021-04-01"
author = "Simon Scannell"
+++


## Core Software vulnerabilities

An incomplete list of all vulnerabilities I ever found!


|Software|Versions|Impact|CVE|Write-Up|
|--- |--- |--- |--- |--- |
|Linux|< 5.8.15|Privilege Escalation|CVE-2020-27194|[Write Up](https://scannell.me/fuzzing-for-ebpf-jit-bugs-in-the-linux-kernel/), [Exploit](https://github.com/scannells/exploits/tree/master/CVE-2020-27194)|
|libGD|<= 2.2.5|PHP imagescale()remote wild free||[HackerOne report](https://hackerone.com/reports/478367)|
|libGD|<= 2.2.5|PHP “Sandbox” escape|CVE-2019-6977|[Exploit](https://github.com/scannells/exploits/blob/master/CVE-2019-6977%20imagecolormatch.php)|
|WordPress|<= 5.3.2|“Sandbox” escape|–|[RIPS Blog](https://blog.ripstech.com/2020/wordpress-hardening-bypass/)|
|WordPress|<= 5.0.0|Unprivileged RCE|CVE-2019-8943|[RIPS Bog](https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/)|
|WordPress|<= 5.1.0|CSRF to RCE|CVE-2019-9787|[RIPS Blog](https://blog.ripstech.com/2019/wordpress-csrf-to-rce/)|
|WordPress|<= 5.0.0|Post Priv Esc|CVE-2018-20152|[RIPS Blog](https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/)|
|WordPress|–|Priv Esc|CVE-2018-20714|[RIPS Blog](https://blog.ripstech.com/2018/wordpress-design-flaw-leads-to-woocommerce-rce/)|
|WordPress||Unprivileged Stored XSS in certain plugins|CVE-2019-16773|[HackerOne report](https://hackerone.com/reports/509930)|
|MyBB|<= 1.8.2|Unprivileged Stored XSS|CVE-2019-12830|[RIPS Blog](https://blog.ripstech.com/2019/mybb-stored-xss-to-rce/)|
|MyBB|<= 1.8.2|Privileged RCE|CVE-2019-12831|[RIPS Blog](https://blog.ripstech.com/2019/mybb-stored-xss-to-rce/)|
|phpBB3|<= 3.2.3|Privileged RCE|CVE-2018-19274|[RIPS Blog](https://blog.ripstech.com/2018/phpbb3-phar-deserialization-to-remote-code-execution/)|
|Pydio|<= 8.2.1|Unauthenticated RCE|CVE-2018-20718|[RIPS Blog](https://blog.ripstech.com/2018/pydio-unauthenticated-remote-code-execution/)|
|Shopware|<= 5.4.3|Privileged RCE|SW-21776|–|
|Magento|<= 2.3.1|Unauthenticated Stored XSS in Admin Dashboard|CVE-2019-7877|[RIPS Blog](https://blog.ripstech.com/2019/magento-rce-via-xss/)|
|Magento|<= 2.3.0|Privileged RCE|PRODSECBUG-2261|[RIPS Blog](https://blog.ripstech.com/2019/magento-rce-via-xss/)|
|Magento|<= 2.3.0|Privileged RCE|PRODSECBUG-2256|–|
|Magento|<= 2.3.1|Privileged RCE|CVE-2019-7932|–|
|Magento|<= 2.3.1|Privileged RCE|CVE-2019-7885|–|
|Magento|<= 2.3.2|Authenticated Stored XSS|CVE-2019-8152|–|
|Magento|<= 2.3.2|escapeURL()bypass|CVE-2019-8153|–|
|Magento|<= 2.3.2|Potential unauthenticated Stored XSS|CVE-2019-8233|–|


## WordPress Plugin Advent Calendar

During my time at RIPS Tech I had the pleasure of setting up the so called “WordPress Plugin Advent Calendar”. In Germany, like in a lot of countries, it is a tradition to give kids a treat every day from the first of December until Christmas eve. At RIPS, we wanted to implement this tradition for the InfoSec people. Each day we either released a vulnerability in a plugin or a core WordPress bug. Many of the plugins featured had millions of active installations and were composed of bugs in eCommerce, forums, Caching etc. Take a look here: [RIPS Advent Calendar 2018](https://www.ripstech.com/php-security-calendar-2018/).

I wrote the Calendar and found a big portion of the vulnerabilities. I received huge amounts of support and help by Dennis Brinkrolf and Karim Elouerghemmi, who were two amazing collegues!

{{< image src="/images/wordpress_calendar.png" caption="The calendar" >}}

