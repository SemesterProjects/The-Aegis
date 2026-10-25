with open('generate_final_report.py', 'r', encoding='utf-8') as f:
    code = f.read()

code = code.replace('output_filename = "AEGIS_Major_Project_Report_Final.docx"', 'output_filename = "AEGIS_Major_Project_Report_Verified.docx"')

with open('generate_final_report.py', 'w', encoding='utf-8') as f:
    f.write(code)

print("Updated output filename.")
