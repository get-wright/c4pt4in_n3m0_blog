---
description: Real cheesy, mate 🧀
cover: ../.gitbook/assets/Certified RED TEAM OPerator.png
coverY: 0
layout:
  cover:
    visible: true
    size: full
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
---

# ⚔ Journey to Certified Red Team Operator (CRTO)

## Th0ugh7s on the certification

I have just passed the Red Team Operator exam on Saturday. In my personal opinion, RTO was both a little bit difficult and enjoyable. Since the exam went a lot differently than I had anticipated, I wanted to share my ideas in hopes that it may help those who are also getting ready for the test.&#x20;

## Wh47 is CRTO?

For penetration testers who wish to progress in their career and become red teamers, the certified red team operator certification is an entry-level to intermediate security certification. The applicant will get a chance to test the strategies, methods that cybercriminals employ to compromise IT systems and evade detection and see how it play out in a controlled environment (thus stay true to the statement of "adversary simulation")

There is a course offers by the same author - Daniel Duggan (aka the one and only RastaMouse). His work on Red Team Ops is phenomenal, and he explains most concepts and tactics in a way that is straightforward. (I didn't purchase the course, so the reflection is based solely on the modules I've learnt by borrowing from friends). I would recommend you to check it out.

## 4b0u7 the exam

### M4in objective

You would have 4 calendar days, and only 48 hours of time in the exam lab environment. No report writing is required, so take your time. Capturing 6 of the 8 flags will earn you a badge that basically saying that I am good at pretending to be a "real bad actor".&#x20;

<figure><img src="../.gitbook/assets/Screenshot 2023-10-29 213118.png" alt=""><figcaption><p>This is my attempt on the exam. Spend around 2 - 3 hours for the first flag. It was 3:00 am in the morning for the 6th flag.</p></figcaption></figure>

The Snap Labs interface allows for the submission of each flag for verification.&#x20;

<figure><img src="../.gitbook/assets/Screenshot 2023-10-29 212336.png" alt=""><figcaption><p>This is where you can access the attacker machines (Both Windows and Linux) and a victim machine (initial access) </p></figcaption></figure>

You have access to a Kali Linux machine, a Windows attack machine, and a machine on the internal network from which you launch your attack (because it's an assumed breach scenario). Snaplab.io provides access through Guacamole so you can run your whole operation on just a few tabs.

* Good: If you have a really reliable & great internet connection, just hop into the lab environment without worrying about anything.
* Bad: Sometimes it would just straight up disconnect (a very minor issue, last only for a few seconds - F5 would solve the problem).

They have also added the option to download a OVPN profile (which is the long-awaited feature).

### Thr34t Profile (Ah! The good old red scare)

This would give you a brief on the hypothetical hacker group, provide some info on your target. The lab also come with a licensed version of Cobalt Strike as the main one to conduct your ops (lol, real Cobalt Strike for the rich, cracked Cobalt Strike for the mad one).

I believe that the majority of the tools offered by the lab are sufficient, but remember, you are unable to import any new tools (~~say goodbye to git cloning toolkits~~).

### Dur1ng the exam (20 hours of pain and tears)

Overall, I consider the exam to be rather challenging, but I've had a great time with it. I passed with 6/8 flags and lost my sanity for the 7th one. But it was 4AM in the morning, so I got to my bed and die :skull:. The path is clearly from the beginning, just find all the machines and pwned them. The nice thing that it wasn't CTF-y in the sense that you had to search in every corner, check every binary on the machine to find a clue on another maze.&#x20;

I mentioned it as entry-level, but it does not suggest that anyone with little knowledge of offensive security would be able to pass the exam.&#x20;

It should be alright if you know:

* The underlying attacks and enumeration required in Active Directory.
* Abusing creds and token for privilege escalation.
* Kerberos, Kerberos, Kerberos
* Every aspect of Windows Defenses in place.

I don't want to spoil anything on the exam, but these are the key aspects you should **AT LEAST** pay attention to.

There will be occasions when you'll need to use a lot of brain cells to assess potential defenses and determine the best course of action. If something isn't working, think about the possible causes, think like a bad guy attempting to break into a corp. Just make a note of every conceivable clue you got because there may be certain paths that surprise you.&#x20;

**AND THE FINAL PIECE OF ADVICE I CAN GIVE YOU IS: PLEASE JUST PREP ALL YOUR TOOLSETS CAREFULLY! I MEAN IT!!!**

### Cobalt Strike huh?

Because most the exam revolved around the use of CS, it is just f\*cking awesome:

* Don't want to load a full fat .exe instance on a machine. Just use `execute-assembly` to run your binaries in memory.
* Easily edit your C2 profiles to change beacon’s in-memory characteristics, to trick a defender that your traffic is legit. Freaking dope!!!
* With Artifact Kit you could modify source code of beacon agents to evade AV and EDR solutions.

Of course, in practice, you should build your own C2 from the ground up because most publicly available tools are likely to be studied & known by most security solutions on the market, or just do your own customizations to bypass it.&#x20;

### H34d1ng for the exam!

If you gonna take this exam or just want a fancy piece of paper to brag with your pals, here are some sources for you to practice & horning your skills:

* [Red Team Ops by ZPS](https://training.zeropointsecurity.co.uk/courses/red-team-ops) - **HIGHLY RECOMMAND THIS COURSE.** Along the way to becoming a red team operator, the knowledge you gain from this course will be useful. You will also have the opportunity to practice in lab and take a free test. (But the price gonna be stiff for some)
* [Throwback Network Labs by TryHackMe](https://tryhackme.com/network/throwback) - You would learn how to breach a Windows network, as well as understand its foundations and key ideas and how to use them to your benefit - just so that you can know the basics. (52GBP on 30 days).
* [RastaLabs by HTB](https://www.hackthebox.com/hacker/pro-labs) - Although being made by the same author, RastaLabs is considerably harder than the CRTO itself (due to the fact that you have to do some of the phishing and some CTF-y challenges). But it is a good way to practice & see how your methodologies in work ($49/month).
* Or just made yourself a homelab (Hard, but free and worth your time).

## Jump psexec to the conclusion!

CRTO was a nice breeze, a fresh take on how a great certification should be. While CRTO by alone won't allow you to sneak past HR's filter like the famous O(e)S(pensive)CP, it is nice to prove & test how evil you can be.

<figure><img src="../.gitbook/assets/image (1).png" alt=""><figcaption><p>A cool badge to put in a LinkdIn account that no one gonna read!</p></figcaption></figure>









