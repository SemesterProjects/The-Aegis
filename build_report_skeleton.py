import os
import sys
import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def create_aegis_report():
    doc = docx.Document()

    # 1. Page Setup per Mumbai University Guidelines:
    # Top Margin : 15 mm (approx 42.5 pt) -> when no header 30 mm (85 pt).
    # Left Margin : 30 mm (85 pt)
    # Right Margin : 20 mm (56.7 pt)
    # Bottom Margin : 22 mm (62.35 pt)
    section = doc.sections[0]
    section.page_width = Pt(595.3)   # Standard A4 width
    section.page_height = Pt(841.9)  # Standard A4 height
    section.top_margin = Pt(85.05)   # 30 mm
    section.bottom_margin = Pt(62.35)# 22 mm
    section.left_margin = Pt(85.05)  # 30 mm
    section.right_margin = Pt(56.7)  # 20 mm

    # Configure base style
    style_normal = doc.styles['Normal']
    font = style_normal.font
    font.name = 'Times New Roman'
    font.size = Pt(12)
    font.color.rgb = RGBColor(0, 0, 0)
    style_normal.paragraph_format.line_spacing = 1.5
    style_normal.paragraph_format.space_after = Pt(6)

    def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = OxmlElement('w:tcMar')
        for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
            node = OxmlElement(f'w:{m}')
            node.set(qn('w:w'), str(val))
            node.set(qn('w:type'), 'dxa')
            tcMar.append(node)
        tcPr.append(tcMar)

    def set_cell_shading(cell, color_hex):
        shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{color_hex}"/>')
        cell._tc.get_or_add_tcPr().append(shading)

    def set_table_borders(table, color="D3D3D3"):
        tblPr = table._tbl.tblPr
        borders = parse_xml(
            f'<w:tblBorders {nsdecls("w")}>'
            f'  <w:top w:val="single" w:sz="6" w:space="0" w:color="{color}"/>'
            f'  <w:left w:val="none"/>'
            f'  <w:bottom w:val="single" w:sz="6" w:space="0" w:color="{color}"/>'
            f'  <w:right w:val="none"/>'
            f'  <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{color}"/>'
            f'  <w:insideV w:val="none"/>'
            f'</w:tblBorders>'
        )
        tblPr.append(borders)

    def add_page_break():
        doc.add_page_break()

    def add_front_cover():
        p1 = doc.add_paragraph()
        p1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p1.paragraph_format.space_before = Pt(20)
        p1.paragraph_format.space_after = Pt(24)
        run1 = p1.add_run("AEGIS: AUTONOMOUS AI FRAMEWORK FOR ZERO-DAY ATTACK DETECTION AND RESPONSE")
        run1.font.name = 'Times New Roman'
        run1.font.size = Pt(22)
        run1.bold = True

        p2 = doc.add_paragraph()
        p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p2.paragraph_format.space_after = Pt(12)
        run2 = p2.add_run("submitted in partial fulfilment of the requirements for\nMajor Project-I Sem-VII\nBachelor of Engineering in Computer Engineering")
        run2.font.name = 'Times New Roman'
        run2.font.size = Pt(14)
        run2.italic = True

        p3 = doc.add_paragraph()
        p3.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p3.paragraph_format.space_before = Pt(18)
        p3.paragraph_format.space_after = Pt(6)
        r3 = p3.add_run("By\n")
        r3.font.name = 'Times New Roman'
        r3.font.size = Pt(14)
        r3.bold = True
        
        candidates = [
            "Ms. Visha Yadav (Roll No. 66)",
            "Ms. Purva Patil (Roll No. 72)",
            "Ms. Bhakti Shingadi (Roll No. 75)"
        ]
        p_cand = doc.add_paragraph()
        p_cand.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cand.paragraph_format.space_after = Pt(18)
        for cand in candidates:
            r = p_cand.add_run(cand + "\n")
            r.font.name = 'Times New Roman'
            r.font.size = Pt(14)
            r.bold = True

        p_guide = doc.add_paragraph()
        p_guide.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_guide.paragraph_format.space_after = Pt(18)
        rg1 = p_guide.add_run("Under the Guidance of\n")
        rg1.font.name = 'Times New Roman'
        rg1.font.size = Pt(14)
        rg2 = p_guide.add_run("Prof. Brinal Colaco")
        rg2.font.name = 'Times New Roman'
        rg2.font.size = Pt(15)
        rg2.bold = True

        # Insert Institute Emblem if extracted
        if os.path.exists("extracted_image_1.jpg"):
            p_img = doc.add_paragraph()
            p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p_img.paragraph_format.space_after = Pt(12)
            run_img = p_img.add_run()
            run_img.add_picture("extracted_image_1.jpg", width=Inches(1.3))

        p_dept = doc.add_paragraph()
        p_dept.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_dept.paragraph_format.space_after = Pt(4)
        rd1 = p_dept.add_run("Department of Computer Engineering\n")
        rd1.font.name = 'Times New Roman'
        rd1.font.size = Pt(14)
        rd1.bold = True
        rd2 = p_dept.add_run("Vidyavardhini’s College of Engineering & Technology, Vasai (W)\n(NAAC and NBA Accredited)\nAffiliated with University of Mumbai\n(2026–2027)")
        rd2.font.name = 'Times New Roman'
        rd2.font.size = Pt(12)

    def add_certificate():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(24)
        r = p_title.add_run("CERTIFICATE")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        p_body = doc.add_paragraph()
        p_body.paragraph_format.line_spacing = 1.5
        p_body.paragraph_format.space_after = Pt(36)
        p_body.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        r_b = p_body.add_run(
            "This is to certify that the project entitled “AEGIS: Autonomous AI Framework for ZeroDay Attack "
            "Detection and Response” is a bonafide work of Ms. Visha Yadav (Roll No. 66), Ms. Purva Patil "
            "(Roll No. 72), and Ms. Bhakti Shingadi (Roll No. 75) submitted to the University of Mumbai in "
            "partial fulfillment of the requirement for the award of the degree of “Bachelor of Engineering” "
            "in “Computer Engineering” during the academic year 2026–2027."
        )
        r_b.font.name = 'Times New Roman'
        r_b.font.size = Pt(12)

        # Signature Table
        table = doc.add_table(rows=2, cols=2)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell_00 = table.cell(0, 0)
        cell_01 = table.cell(0, 1)
        cell_10 = table.cell(1, 0)
        cell_11 = table.cell(1, 1)

        def fill_sig(cell, name, designation):
            p = cell.paragraphs[0]
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(30)
            p.paragraph_format.space_after = Pt(20)
            r = p.add_run(f"__________________________\n{name}\n{designation}")
            r.font.name = 'Times New Roman'
            r.font.size = Pt(11)
            r.bold = True

        fill_sig(cell_00, "Prof. Brinal Colaco", "Project Guide")
        fill_sig(cell_01, "Prof. Brinal Colaco", "Project Guide")
        fill_sig(cell_10, "Dr. Megha Trivedi", "Head of Department")
        fill_sig(cell_11, "Dr. Rakesh Himte", "Principal")

    def add_approval_sheet():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(24)
        r = p_title.add_run("Project Report Approval for B.E.")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        p_body = doc.add_paragraph()
        p_body.paragraph_format.line_spacing = 1.5
        p_body.paragraph_format.space_after = Pt(36)
        p_body.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        r_b = p_body.add_run(
            "This project report entitled “AEGIS: Autonomous AI Framework for ZeroDay Attack Detection "
            "and Response” by Visha Yadav, Purva Patil, and Bhakti Shingadi is approved for the degree of "
            "“Bachelor of Engineering” in “Computer Engineering”."
        )
        r_b.font.name = 'Times New Roman'
        r_b.font.size = Pt(12)

        p_exam = doc.add_paragraph()
        p_exam.paragraph_format.space_before = Pt(24)
        r_ex = p_exam.add_run("Examiners:\n\n1. __________________________\n\n2. __________________________\n\n")
        r_ex.font.name = 'Times New Roman'
        r_ex.font.size = Pt(12)

        p_date = doc.add_paragraph()
        r_d = p_date.add_run("Date:\nPlace: Vasai")
        r_d.font.name = 'Times New Roman'
        r_d.font.size = Pt(12)

    def add_declaration():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(24)
        r = p_title.add_run("Declaration")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        p_body = doc.add_paragraph()
        p_body.paragraph_format.line_spacing = 1.5
        p_body.paragraph_format.space_after = Pt(30)
        p_body.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        r_b = p_body.add_run(
            "We declare that this written submission represents our ideas in our own words and where others’ "
            "ideas or words have been included, we have adequately cited and referenced the original sources. "
            "We also declare that we have adhered to all principles of academic honesty and integrity and have "
            "not misrepresented or fabricated or falsified any idea/data/fact/source in our submission. We "
            "understand that any violation of the above will be cause for disciplinary action by the Institute "
            "and can also evoke penal action from the sources which have thus not been properly cited or from "
            "whom proper permission has not been taken when needed."
        )
        r_b.font.name = 'Times New Roman'
        r_b.font.size = Pt(12)

        p_sig = doc.add_paragraph()
        p_sig.paragraph_format.space_before = Pt(30)
        p_sig.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        r_s = p_sig.add_run(
            "------------------------------------\n"
            "Visha Yadav (Roll No. 66)\n\n"
            "------------------------------------\n"
            "Purva Patil (Roll No. 72)\n\n"
            "------------------------------------\n"
            "Bhakti Shingadi (Roll No. 75)\n\n"
            "Date: 24th October 2026\n"
        )
        r_s.font.name = 'Times New Roman'
        r_s.font.size = Pt(12)

    def add_acknowledgements():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(24)
        r = p_title.add_run("Acknowledgements")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        p_ack = doc.add_paragraph()
        p_ack.paragraph_format.line_spacing = 1.5
        p_ack.paragraph_format.space_after = Pt(14)
        p_ack.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p_ack.add_run(
            "We express our sincere gratitude to our Head of Department, Dr. Megha Trivedi, and our project mentor, "
            "Prof. Brinal Colaco, for their invaluable guidance, continuous support, and constructive encouragement "
            "throughout the course of this major project. Their deep technical expertise, meticulous reviews, and insightful "
            "suggestions played a decisive role in shaping the architectural rigor, system safety governance, and execution "
            "integrity of our work on AEGIS."
        )

        p_ack2 = doc.add_paragraph()
        p_ack2.paragraph_format.line_spacing = 1.5
        p_ack2.paragraph_format.space_after = Pt(14)
        p_ack2.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p_ack2.add_run(
            "We gratefully acknowledge the Department of Computer Engineering, Vidyavardhini’s College of Engineering "
            "& Technology, for providing us with the necessary computing infrastructure, lab resources, and a highly "
            "supportive academic environment that enabled us to conduct runtime monitoring, operating system kernel "
            "telemetry tracing, and automated validation tests successfully."
        )

        p_ack3 = doc.add_paragraph()
        p_ack3.paragraph_format.line_spacing = 1.5
        p_ack3.paragraph_format.space_after = Pt(14)
        p_ack3.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p_ack3.add_run(
            "We also extend our sincere thanks to our classmates and peer reviewers for their constant motivation, "
            "adversarial testing feedback, and constructive recommendations during the development and experimental "
            "evaluation phases. Finally, we thank our parents and all well-wishers whose unwavering encouragement and "
            "faith supported us at every stage of this project."
        )

        p_sig = doc.add_paragraph()
        p_sig.paragraph_format.space_before = Pt(24)
        p_sig.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p_sig.add_run(
            "------------------------------------\n"
            "Visha Yadav (Roll No. 66)\n"
            "Purva Patil (Roll No. 72)\n"
            "Bhakti Shingadi (Roll No. 75)\n"
        )

    def add_abstract():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(24)
        r = p_title.add_run("Abstract")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        paragraphs = [
            "Modern enterprise computing infrastructures face severe, escalating security vulnerabilities caused by "
            "zero-day exploits and sophisticated advanced persistent threats (APTs). Conventional endpoint defense "
            "mechanisms rely predominantly on signature-matching engines, known indicators of compromise (IoCs), and static "
            "rule configurations. While effective against commoditized malware, these legacy systems inherently fail to "
            "detect novel, unseen exploit patterns or Living-off-the-Land (LotL) attack techniques that manipulate legitimate "
            "operating system utilities without triggering known static signatures. Furthermore, existing commercial "
            "Endpoint Detection and Response (EDR) platforms suffer from high false-positive alert volumes, severe alert "
            "fatigue among security operations center (SOC) analysts, opaque proprietary machine-learning heuristics, and "
            "either completely manual incident triage or hazardous, unverified automated remediation actions that risk "
            "production system disruption.",

            "To systematically resolve these critical industry challenges, this project presents AEGIS (Autonomous AI "
            "Framework for Zero-Day Attack Detection and Response)—a robust, explainable, and safety-governed endpoint "
            "security monitoring and autonomous investigation architecture. AEGIS implements an end-to-end telemetry and "
            "reasoning pipeline engineered from the ground up for cross-platform fidelity across Windows, Linux, and macOS "
            "environments. The foundation of the framework is built upon five foundational design principles: (1) Observe "
            "before acting, (2) Reason before responding, (3) Verify before deployment, (4) Explain every decision, and (5) "
            "Enforce human authority as the final gatekeeper for production mutations.",

            "During Semester VII (Major Project-I), the active engineering implementation focused on establishing the core "
            "observability, storage, detection, triage, and autonomous investigation primitives. The implemented framework "
            "comprises: (i) a multi-subsystem telemetry engine collecting process lifecycle events, file modifications (via "
            "Watchdog API and polling fallback), authentication failures (via Windows Event Log wevtutil and Linux journalctl), "
            "and socket connection snapshots via psutil; (ii) a canonical Universal Event Model (UEM) normalizing divergent "
            "host telemetry into strongly typed, immutable schemas; (iii) a tamper-evident SQLite Evidence Store secured with an "
            "append-only SHA-256 cryptographic hash chain; (iv) a deterministic behavioral detection pipeline with four "
            "explainable non-signature detectors (AuthFailureBurstDetector, FileChangeBurstDetector, NetworkRateDetector, and "
            "NewProcessWithNetworkDetector); (v) a multi-signal Triage Engine scoring composite risks and packaging high-confidence "
            "Investigation Cases; (vi) an autonomous, goal-driven Investigation Agent executing an adaptive, budget-bounded hypothesis "
            "evaluation loop over in-memory correlation indices and temporal timelines without direct system mutation; and (vii) an "
            "approval-gated File Version Vault enforcing human authorization before executing any file restoration.",

            "The Semester VII implementation has been rigorously validated through an automated test suite comprising 256 "
            "deterministic unit and integration tests, alongside end-to-end host telemetry validation scenarios. In this report, "
            "all implemented capabilities, mathematical formulations, structural designs, data flow architectures, and empirical "
            "benchmarks are documented in full technical depth. Crucially, the engineering boundaries are transparently demarcated: "
            "kernel-level eBPF tracing, ETW real-time consumers, generative adversarial vulnerability hunting (Aegis Forge), "
            "automated isolated sandbox patch verification, and full production mitigations represent the planned roadmap for "
            "Semester VIII."
        ]

        for p_text in paragraphs:
            p = doc.add_paragraph()
            p.paragraph_format.line_spacing = 1.5
            p.paragraph_format.space_after = Pt(10)
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.add_run(p_text)

        p_kw = doc.add_paragraph()
        p_kw.paragraph_format.space_before = Pt(12)
        r_kwh = p_kw.add_run("Keywords: ")
        r_kwh.bold = True
        p_kw.add_run("Zero-Day Exploits, Autonomous AI Investigation, Endpoint Detection and Response (EDR), Universal Event Model (UEM), Cryptographic Hash-Chain, Behavioral Anomaly Detection, Human-in-the-Loop Governance.")

    def add_table_of_contents():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(24)
        r = p_title.add_run("Contents")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        toc_data = [
            ("Chapter No.", "Particulars", "Pg. No."),
            ("1", "Introduction", "1"),
            ("", "1.1 Background", "1"),
            ("", "1.2 Literature Survey", "3"),
            ("", "1.3 Limitations of Existing Systems", "7"),
            ("", "1.4 Problem Statement and Objectives", "9"),
            ("2", "Proposed System", "11"),
            ("", "2.1 System Analysis", "11"),
            ("", "    2.1.1 Hardware and Software Requirements", "12"),
            ("", "    2.1.2 Functional Requirements", "13"),
            ("", "    2.1.3 Non-Functional Requirements", "15"),
            ("", "2.2 Algorithms and Detection Formulations", "16"),
            ("", "2.3 System Design Details", "21"),
            ("", "    2.3.1 System Architectural Decomposition", "21"),
            ("", "    2.3.2 Data Flow Diagrams (DFD Level 0 & Level 1)", "23"),
            ("", "    2.3.3 UML Class & Component Models", "25"),
            ("3", "Methodology and Implementation Details", "27"),
            ("", "3.1 Architectural Modules of AEGIS", "27"),
            ("", "    3.1.1 Telemetry Collection Subsystem", "27"),
            ("", "    3.1.2 Universal Event Normalization Model (UEM)", "29"),
            ("", "    3.1.3 Cryptographic Evidence Integrity (Hash-Chain)", "31"),
            ("", "    3.1.4 Temporal & In-Memory Correlation Indexing", "32"),
            ("", "    3.1.5 Non-Signature Behavioral Detection Pipeline", "33"),
            ("", "    3.1.6 Deterministic Multi-Signal Triage Engine", "34"),
            ("", "    3.1.7 Adaptive Goal-Driven Investigation Agent", "35"),
            ("", "    3.1.8 Quota-Bounded Version Vault & Human Approval Gate", "37"),
            ("4", "Experimental Setup", "39"),
            ("", "4.1 Details of Database, System Telemetry, and Input Data", "39"),
            ("", "4.2 Performance Evaluation Parameters (for Validation)", "42"),
            ("", "4.3 Software and Hardware Experimental Environment", "45"),
            ("5", "Implementation Plan for Next Semester", "47"),
            ("", "5.1 Timeline Chart for Sem-VII and Sem-VIII (Gantt Chart)", "47"),
            ("", "5.2 Planned Modules and Methodologies for Semester VIII", "49"),
            ("6", "Implementation Results and Validation", "51"),
            ("", "6.1 Telemetry Collection and Normalization Verification", "51"),
            ("", "6.2 Behavioral Detection and Triage Scoring Evaluation", "53"),
            ("", "6.3 Autonomous Investigation Execution and Timeline Reconstruction", "55"),
            ("", "6.4 Evidence Store Hash-Chain Tamper Detection Benchmarks", "57"),
            ("", "6.5 Comprehensive Test Suite Execution Analysis (256 Tests)", "58"),
            ("7", "Conclusion and Limitations", "61"),
            ("", "7.1 Summary of Semester VII Contributions", "61"),
            ("", "7.2 Honest Identification of System Limitations and Gaps", "62"),
            ("", "7.3 Future Scope and Research Roadmap", "63"),
            ("8", "Plagiarism Report", "65"),
            ("9", "References", "66"),
        ]

        table = doc.add_table(rows=len(toc_data), cols=3)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        set_table_borders(table)
        for i, row in enumerate(toc_data):
            for j, val in enumerate(row):
                cell = table.cell(i, j)
                cell.text = val
                p = cell.paragraphs[0]
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(2)
                p.paragraph_format.space_before = Pt(2)
                run = p.runs[0]
                run.font.name = 'Times New Roman'
                run.font.size = Pt(11)
                if i == 0 or (val and j == 0) or (row[0] != "" and j == 1):
                    run.bold = True
                if i == 0:
                    set_cell_shading(cell, "F2F2F2")

    def add_list_of_figures_and_tables():
        add_page_break()
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_title.paragraph_format.space_before = Pt(36)
        p_title.paragraph_format.space_after = Pt(20)
        r = p_title.add_run("List of Figures")
        r.font.name = 'Times New Roman'
        r.font.size = Pt(18)
        r.bold = True

        fig_data = [
            ("Figure Number", "Description", "Page Number"),
            ("2.1", "AEGIS Three-Tier Framework and Pipeline Architecture", "22"),
            ("2.2", "Data Flow Diagram (Level 0 and Level 1 Telemetry Pipeline)", "24"),
            ("2.3", "Adaptive Goal-Driven Investigation Loop State Transitions", "26"),
            ("3.1", "Append-Only Cryptographic SHA-256 Hash Chain Structure", "31"),
            ("5.1", "Gantt Chart Showing Sem-VII Progress and Sem-VIII Implementation Plan", "48"),
            ("6.1", "Deterministic Unit and Integration Test Suite Execution Output (256 Passed)", "59"),
            ("6.2", "End-to-End Investigation Case Packaging and Evidence Graph Result", "60"),
        ]

        tbl_figs = doc.add_table(rows=len(fig_data), cols=3)
        tbl_figs.alignment = WD_TABLE_ALIGNMENT.CENTER
        set_table_borders(tbl_figs)
        for i, row in enumerate(fig_data):
            for j, val in enumerate(row):
                cell = tbl_figs.cell(i, j)
                cell.text = val
                p = cell.paragraphs[0]
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(2)
                p.paragraph_format.space_before = Pt(2)
                run = p.runs[0]
                run.font.name = 'Times New Roman'
                run.font.size = Pt(11)
                if i == 0:
                    run.bold = True
                    set_cell_shading(cell, "F2F2F2")

        p_tbl_title = doc.add_paragraph()
        p_tbl_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_tbl_title.paragraph_format.space_before = Pt(36)
        p_tbl_title.paragraph_format.space_after = Pt(20)
        r2 = p_tbl_title.add_run("List of Tables")
        r2.font.name = 'Times New Roman'
        r2.font.size = Pt(18)
        r2.bold = True

        tbl_headers = [
            ("Table Number", "Description", "Page Number"),
            ("1.1", "Comparative Analysis of Endpoint Security and Incident Response Frameworks", "8"),
            ("2.1", "Triage Signal Weights and Risk Attribution Scoring Metrics", "18"),
            ("2.2", "Hardware Requirements and Experimental Workstation Specifications", "12"),
            ("2.3", "Software Requirements and Production Environment Toolchain", "13"),
            ("3.1", "Universal Event Model (UEM) Canonical Schema Attributes", "30"),
            ("3.2", "Implemented Behavioral Detectors and Heuristic Boundary Specifications", "33"),
            ("4.1", "Software Environment and Supporting Technologies", "45"),
            ("4.2", "Hardware Configuration for Experimental Host and Virtualized Nodes", "46"),
            ("5.1", "Semester VII Implemented Modules vs. Semester VIII Planned Enhancements", "50"),
            ("6.1", "Empirical Test Suite Breakdown Across Subsystems (Total 256 Tests)", "58"),
        ]

        tbl_tables = doc.add_table(rows=len(tbl_headers), cols=3)
        tbl_tables.alignment = WD_TABLE_ALIGNMENT.CENTER
        set_table_borders(tbl_tables)
        for i, row in enumerate(tbl_headers):
            for j, val in enumerate(row):
                cell = tbl_tables.cell(i, j)
                cell.text = val
                p = cell.paragraphs[0]
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(2)
                p.paragraph_format.space_before = Pt(2)
                run = p.runs[0]
                run.font.name = 'Times New Roman'
                run.font.size = Pt(11)
                if i == 0:
                    run.bold = True
                    set_cell_shading(cell, "F2F2F2")

        # Abbreviations List
        p_abb_title = doc.add_paragraph()
        p_abb_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_abb_title.paragraph_format.space_before = Pt(36)
        p_abb_title.paragraph_format.space_after = Pt(20)
        r3 = p_abb_title.add_run("List of Abbreviations")
        r3.font.name = 'Times New Roman'
        r3.font.size = Pt(18)
        r3.bold = True

        abbs = [
            ("Abbreviation", "Expanded Definition"),
            ("AEGIS", "Autonomous AI Framework for Zero-Day Attack Detection and Response"),
            ("AI", "Artificial Intelligence"),
            ("APT", "Advanced Persistent Threat"),
            ("C2", "Command and Control"),
            ("DFD", "Data Flow Diagram"),
            ("eBPF", "Extended Berkeley Packet Filter"),
            ("EDR", "Endpoint Detection and Response"),
            ("ETW", "Event Tracing for Windows"),
            ("HIDS", "Host-based Intrusion Detection System"),
            ("IoC", "Indicator of Compromise"),
            ("LLM", "Large Language Model"),
            ("LotL", "Living-off-the-Land (techniques)"),
            ("NIDS", "Network-based Intrusion Detection System"),
            ("PID", "Process Identifier"),
            ("PPID", "Parent Process Identifier"),
            ("RBAC", "Role-Based Access Control"),
            ("SHA", "Secure Hash Algorithm"),
            ("SIEM", "Security Information and Event Management"),
            ("SOAR", "Security Orchestration, Automation, and Response"),
            ("SOC", "Security Operations Center"),
            ("UEM", "Universal Event Model"),
            ("UML", "Unified Modeling Language"),
            ("UUID", "Universally Unique Identifier"),
            ("WAL", "Write-Ahead Logging"),
            ("XDR", "Extended Detection and Response"),
        ]

        tbl_abbs = doc.add_table(rows=len(abbs), cols=2)
        tbl_abbs.alignment = WD_TABLE_ALIGNMENT.CENTER
        set_table_borders(tbl_abbs)
        for i, row in enumerate(abbs):
            for j, val in enumerate(row):
                cell = tbl_abbs.cell(i, j)
                cell.text = val
                p = cell.paragraphs[0]
                p.paragraph_format.line_spacing = 1.15
                p.paragraph_format.space_after = Pt(2)
                p.paragraph_format.space_before = Pt(2)
                run = p.runs[0]
                run.font.name = 'Times New Roman'
                run.font.size = Pt(11)
                if i == 0:
                    run.bold = True
                    set_cell_shading(cell, "F2F2F2")

    # Build initial structure
    add_front_cover()
    add_certificate()
    add_approval_sheet()
    add_declaration()
    add_acknowledgements()
    add_abstract()
    add_table_of_contents()
    add_list_of_figures_and_tables()

    # Save initial skeleton
    doc.save("AEGIS_Major_Project_Report_Final.docx")
    print("Skeleton report initialized successfully.")

if __name__ == "__main__":
    create_aegis_report()
