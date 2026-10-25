import re

with open('generate_final_report.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Replace Table of Contents items
text = text.replace('("", "       3.2 Cryptography (Evidence Hash-Chain)", "31"),', '("", "3.2 Evidence Integrity and Append-Only Hash Chaining", "31"),')
text = text.replace('("", "3.2.1 Behavioral Detection Subsystem", "33"),', '("", "3.3 Explainable Non-Signature Behavioral Detectors", "33"),')
text = text.replace('("", "3.2.2. Autonomous Investigation & Triage Engine", "34"),', '("", "3.4 Autonomous Investigation Loop and Triage Engine", "34"),')

# Replace Section Headers in Chapter 3
text = text.replace('add_section_header("3.2", "Cryptography")', 'add_section_header("3.2", "Evidence Integrity and Append-Only Hash Chaining")')
text = text.replace('add_subsection_header("3.2.1", "Steganography / Behavioral Detection Subsystem")', 'add_section_header("3.3", "Explainable Non-Signature Behavioral Detectors")')
text = text.replace('add_subsection_header("3.2.2", "Autonomous Investigation & Triage Engine")', 'add_section_header("3.4", "Autonomous Investigation Loop and Triage Engine")')

# Replace the steganography paragraph
old_p = (
    '    add_body_paragraph(\n'
    '        "Note: While traditional cryptographic systems frequently pair encryption with steganographic concealment, in the context of endpoint "\n'
    '        "security engineering and zero-day defense, AEGIS applies behavioral anomaly heuristics to detect \'steganographic\' or concealed malicious "\n'
    '        "activity (such as Living-off-the-Land obfuscation and hidden command-and-control channels)."\n'
    '    )'
)
new_p = (
    '    add_body_paragraph(\n'
    '        "The behavioral detection subsystem in AEGIS replaces signature-matching with deterministic streaming heuristics. "\n'
    '        "Rather than scanning static binary patterns, AEGIS evaluates temporal event sequences across processes, files, "\n'
    '        "network sockets, and authentication attempts to identify suspicious behaviors characteristic of zero-day attacks."\n'
    '    )'
)
text = text.replace(old_p, new_p)

# Replace textual diagram with generated image
old_diag = (
    '    # Textual diagram representation of hash chain\n'
    '    add_body_paragraph(\n'
    '        "[Event Record 1: H_1 = SHA256(H_0 + E_1)] ---> [Event Record 2: H_2 = SHA256(H_1 + E_2)] ---> [Event Record 3: H_3 = SHA256(H_2 + E_3)]"\n'
    '    )\n'
    '    add_caption("Figure 3.1: Append-Only Cryptographic SHA-256 Hash Chain Structure", is_table=False)'
)
new_diag = '    add_image_box("fig_hash_chain.png", 6.0, "Figure 3.1: Append-Only Cryptographic SHA-256 Hash Chain Structure in EvidenceStore")'
text = text.replace(old_diag, new_diag)

with open('generate_final_report.py', 'w', encoding='utf-8') as f:
    f.write(text)

print("generate_final_report.py successfully sanitized and updated.")
