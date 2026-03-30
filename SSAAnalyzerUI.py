import tkinter as tk
from tkinter import scrolledtext, messagebox
from program_analyzer import ProgramVerifier, SSAToSMTCoverter, SMTSolver, ProgramEquivalenceChecker
import graphviz  # Import Graphviz
import re  # Add at top if not already imported

class SSAAnalyzerUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SSA2SMT Analyzer")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f0f8ff")

        self.verifier = ProgramVerifier()
        self.converter = SSAToSMTCoverter(self.verifier.assertions_in_code, self.verifier.variable_versions, self.verifier.unrolling_depth)
        self.solver = SMTSolver()
        self.equivalence_checker = ProgramEquivalenceChecker()

        self.mode = tk.StringVar(value="verification")
        self.unroll_depth = tk.StringVar(value="3")

        self.init_mode_selection_screen()

    def init_mode_selection_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="SSA2SMT Analyzer", font=("Helvetica", 28, "bold"), bg="#f0f8ff", fg="#003366").pack(pady=(40, 30))
        tk.Label(self.root, text="Mode Selection", font=("Helvetica", 26, "bold"), bg="#f0f8ff", fg="#003366").pack(pady=(70, 10))
        tk.Label(self.root, text="Choose between verification mode for a single program or equivalence mode for comparing two programs.",
                 font=("Helvetica", 14), bg="#f0f8ff", fg="#003366", wraplength=800, justify="center").pack(pady=(0, 40))

        mode_frame = tk.Frame(self.root, bg="#f0f8ff")
        mode_frame.pack(pady=10)

        self.make_gradient_label(mode_frame, "Verification Mode", lambda: self.set_mode_and_continue("verification"))
        self.make_gradient_label(mode_frame, "Equivalence Mode", lambda: self.set_mode_and_continue("equivalence"))

    def make_gradient_label(self, parent, text, command):
        tk.Button(parent, text=text, font=("Helvetica", 14), width=20, height=2,
                  bg="#fce303", fg="#003366", relief="raised", bd=3, command=command).pack(padx=20, pady=10, side=tk.LEFT)

    def set_mode_and_continue(self, mode):
        self.mode.set(mode)
        self.init_input_screen()

    def init_input_screen(self):
        self.clear_screen()

        tk.Label(self.root, text=f"{self.mode.get().capitalize()} Mode - Input Code", font=("Helvetica", 20, "bold"),
                 bg="#f0f8ff", fg="#003366").pack(pady=20)

        depth_frame = tk.Frame(self.root, bg="#f0f8ff")
        tk.Label(depth_frame, text="Loop Unroll Depth:", font=("Helvetica", 12), bg="#f0f8ff").pack(side=tk.LEFT)
        tk.Spinbox(depth_frame, from_=1, to=20, textvariable=self.unroll_depth, width=5, font=("Helvetica", 12)).pack(side=tk.LEFT, padx=5)
        depth_frame.pack(pady=5)

        if self.mode.get() == "equivalence":
            input_frame = tk.Frame(self.root, bg="#f0f8ff")
            input_frame.pack(pady=5)

            left_frame = tk.Frame(input_frame, bg="#f0f8ff")
            right_frame = tk.Frame(input_frame, bg="#f0f8ff")
            left_frame.pack(side=tk.LEFT, padx=10)
            right_frame.pack(side=tk.LEFT, padx=10)

            tk.Label(left_frame, text="Program 1 Input", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
            self.code_input_1 = scrolledtext.ScrolledText(left_frame, width=48, height=10)
            self.code_input_1.insert(tk.END, "Enter program 1 code here...")
            self.code_input_1.pack()
            self.code_input_1.bind("<FocusIn>", lambda e: self.clear_placeholder(self.code_input_1, "Enter program 1 code here..."))

            tk.Label(right_frame, text="Program 2 Input", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
            self.code_input_2 = scrolledtext.ScrolledText(right_frame, width=48, height=10)
            self.code_input_2.insert(tk.END, "Enter program 2 code here...")
            self.code_input_2.pack()
            self.code_input_2.bind("<FocusIn>", lambda e: self.clear_placeholder(self.code_input_2, "Enter program 2 code here..."))
        else:
            input_frame = tk.Frame(self.root, bg="#f0f8ff")
            input_frame.pack(pady=10)
            
            # Add postcondition text box
            postcond_frame = tk.Frame(self.root, bg="#f0f8ff")
            postcond_frame.pack(pady=5)
            tk.Label(postcond_frame, text="Postcondition", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
            self.postcond_input = scrolledtext.ScrolledText(postcond_frame, width=96, height=3)
            self.postcond_input.insert(tk.END, "Enter postcondition here...")
            self.postcond_input.pack()
            self.postcond_input.bind("<FocusIn>", lambda e: self.clear_placeholder(self.postcond_input, "Enter postcondition here..."))
            
            tk.Label(input_frame, text="Program Input", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
            self.code_input = scrolledtext.ScrolledText(input_frame, width=96, height=10)
            self.code_input.insert(tk.END, "Enter your program here...")
            self.code_input.pack()
            self.code_input.bind("<FocusIn>", lambda e: self.clear_placeholder(self.code_input, "Enter your program here..."))

        output_frame = tk.Frame(self.root, bg="#f0f8ff")
        output_frame.pack(pady=10)

        ssa_frame = tk.Frame(output_frame, bg="#f0f8ff")
        smt_frame = tk.Frame(output_frame, bg="#f0f8ff")
        smt_final_frame = tk.Frame(output_frame, bg="#f0f8ff")

        tk.Label(ssa_frame, text="SSA Output", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
        self.ssa_output = scrolledtext.ScrolledText(ssa_frame, width=32, height=15)
        self.ssa_output.pack()
        ssa_frame.pack(side=tk.LEFT, padx=10)

        tk.Label(smt_frame, text="SMT Output", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
        self.smt_output = scrolledtext.ScrolledText(smt_frame, width=32, height=15)
        self.smt_output.pack()
        smt_frame.pack(side=tk.LEFT, padx=10)

        tk.Label(smt_final_frame, text="Result", font=("Helvetica", 14, "bold"), bg="#f0f8ff").pack()
        self.smt_final_output = scrolledtext.ScrolledText(smt_final_frame, width=32, height=15)
        self.smt_final_output.pack()
        smt_final_frame.pack(side=tk.LEFT, padx=10)


        tk.Button(self.root, text="Back", command=self.init_mode_selection_screen,
                  bg="#ffd700", fg="black", font=("Helvetica", 12), width=15).place(relx=0.03, rely=0.95, anchor="sw")

        tk.Button(self.root, text="Solve", command=self.run_analysis,
                  bg="#ffd700", fg="black", font=("Helvetica", 12), width=15).place(relx=0.98, rely=0.95, anchor="se")

    def clear_placeholder(self, widget, placeholder):
        if widget.get("1.0", tk.END).strip() == placeholder:
            widget.delete("1.0", tk.END)

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
    

    def is_valid_assert_statement(self, line):
        # Match simple: e.g assert(x == 4);
        simple_assert_pattern = re.compile(r'^assert\s*\(\s*[^\)]+\);\s*$')

        # Match complex: assert(for (i in range(n)) : arr[i] < arr[i+1]);
        for_assert_pattern = re.compile(r'^assert\s*\(\s*for\s*\(.*\)\s*:\s*.+\);\s*$')

        return bool(simple_assert_pattern.match(line) or for_assert_pattern.match(line))


    def is_valid_c_like_code(self, code_lines):
        assignment_pattern = re.compile(r'\s*\w+\s*:=\s*[^;]+;')
        increment_pattern = re.compile(r'\s*\w+\s*(\+\+|:=\s*\w+\s*[\+\-*/]\s*\w+);')
        control_structure_pattern = re.compile(
            r'\s*(if|else\s*if|while|for|do)\s*\(.*\)\s*{'          # regular control structures
            r'|}\s*(?:\s|\n)*else\s*(?:\s|\n)*{'                    # } else { with any spaces/newlines between
            r'|else\s*(?:\s|\n)*{'                                  # else { with any spaces/newlines between
        )

        # closing_brace_pattern = re.compile(r'\s*}')
        valid_statement_pattern = re.compile(r'.*;')

        for line in code_lines:
            line = line.strip()
            if not line or line.startswith("//"):  # Skip empty lines/comments
                continue
            if any(kw in line for kw in ["if", "else", "else if", "while", "for", "do"]):
                if not control_structure_pattern.match(line):
                    return False, f"Invalid control structure format: {line}"
            elif line == "}":
                continue
            elif ":=" in line:
                if not (assignment_pattern.match(line) or increment_pattern.match(line)):
                    return False, f"Invalid assignment or increment: {line}"
            elif not valid_statement_pattern.match(line) and line != "}":
                return False, f"Missing semicolon or invalid statement: {line}"

        return True, ""
    

  

    
    def run_analysis(self):
        try:
            depth = int(self.unroll_depth.get())
        except ValueError:
            self.ssa_output.delete("1.0", tk.END)
            self.smt_output.delete("1.0", tk.END)
            # self.smt_output.delete("1.0", tk.END)
            self.smt_output.insert(tk.END, "Error: Invalid unroll depth.")
            return

        if self.mode.get() == "equivalence":
            program_1_code = self.code_input_1.get("1.0", tk.END).strip().splitlines()
            program_2_code = self.code_input_2.get("1.0", tk.END).strip().splitlines()

            # Check if either program input is empty or contains the placeholder
            if not program_1_code or not program_2_code or \
               all(line.strip() == "" for line in program_1_code) or \
               all(line.strip() == "" for line in program_2_code) or \
               all(line.strip() == "Enter program 1 code here..." for line in program_1_code) or \
               all(line.strip() == "Enter program 2 code here..." for line in program_2_code):
                tk.messagebox.showerror("Input Error", "Both program inputs must be provided.")
                return

            if program_1_code:
                is_valid, error_message = self.is_valid_c_like_code(program_1_code)
                if not is_valid:
                    tk.messagebox.showerror("Invalid Format in Program 1", error_message)
                    return

            if program_2_code:
                is_valid, error_message = self.is_valid_c_like_code(program_2_code)
                if not is_valid:
                    tk.messagebox.showerror("Invalid Format in program 2", error_message)
                    return
                
                 # Validate assertions in the program code
            for line in program_1_code:
                if not self.is_valid_assert_statement(line):
                    tk.messagebox.showerror("Invalid Assertion in program 1", f"Invalid assertion statement: {line}")
                    return
            
            for line in program_2_code:
                if not self.is_valid_assert_statement(line):
                    tk.messagebox.showerror("Invalid Assertion in program 2", f"Invalid assertion statement: {line}")
                    return


            checker = ProgramEquivalenceChecker()
            checker.program_verifier.extract_unroll_depth = lambda _: depth
            checker.ssa_to_smt_converter = SSAToSMTCoverter(self.verifier.assertions_in_code)

            is_equiv, result, combined_smt = checker.check_program_equivalence(program_1_code, program_2_code)

            # SSA for both programs
            checker.program_verifier.variable_versions = {}
            checker.program_verifier.ssa_lines = []
            checker.program_verifier.convert_into_ssa(program_1_code)
            ssa_output = "===== Program 1 SSA =====\n" + "\n".join(checker.program_verifier.ssa_lines)

            checker.program_verifier.variable_versions = {}
            checker.program_verifier.ssa_lines = []
            checker.program_verifier.convert_into_ssa(program_2_code)
            ssa_output += "\n\n===== Program 2 SSA =====\n" + "\n".join(checker.program_verifier.ssa_lines)

            self.ssa_output.delete("1.0", tk.END)
            self.ssa_output.insert(tk.END, ssa_output)

            # SMT + Solver result
            smt_lines = combined_smt  # Use combined SMT lines directly
            self.smt_output.delete("1.0", tk.END)
            self.smt_output.insert(tk.END, "\n".join(smt_lines))  # Display combined SMT in smt_output

            # Display equivalence check result in smt_final_output
            smt_output = f"===== Equivalence Check Result =====\n"
            if is_equiv:
                smt_output += "✓ The programs are equivalent!\n\n"
            else:
                smt_output += "✗ The programs are NOT equivalent!\n\n"

            smt_output += f"SMT Solver Status: {result['status']}\n"
            if result['model']:
                smt_output += "\nModel (Variable Values):\n"
                for var, val in result['model'].items():
                    smt_output += f"  {var} = {val}\n"

            self.smt_final_output.delete("1.0", tk.END)
            self.smt_final_output.insert(tk.END, smt_output)  # Display result in smt_final_output

            # Display control flow graph after 5 seconds
            self.root.after(5000, self.display_control_flow_graph, program_1_code, checker.program_verifier.ssa_lines)

        else: # VERIFICATION MODE.
            program_code = self.code_input.get("1.0", tk.END).strip().splitlines()

            # Check if program input is empty or contains the placeholder
            if not program_code or program_code == [""] or all(line.strip() == "Enter your program here..." for line in program_code):
                tk.messagebox.showerror("Input Error", "Program input cannot be empty.")
                return
            
            if program_code:
                is_valid, error_message = self.is_valid_c_like_code(program_code)
                if not is_valid:
                    tk.messagebox.showerror("Invalid Format", error_message)
                    return
            

            self.verifier = ProgramVerifier()
            self.verifier.extract_unroll_depth = lambda _: depth
            self.verifier.unrolling_depth = depth
            self.verifier.convert_into_ssa(program_code)

            ssa_lines = self.verifier.ssa_lines
            self.ssa_output.delete("1.0", tk.END)
            self.ssa_output.insert(tk.END, "\n".join(ssa_lines))

            # Get postcondition input
            postcondition = self.postcond_input.get("1.0", tk.END).strip()
            if postcondition and postcondition != "Enter postcondition here...":
                self.verifier.postcondition_stuff(postcondition)

            if postcondition and postcondition != "Enter postcondition here...":
                if not self.is_valid_assert_statement(postcondition):
                    tk.messagebox.showerror("Invalid Assertion", f"Invalid assertion statement: {postcondition}")
                    return



            self.converter = SSAToSMTCoverter(self.verifier.assertions_in_code, self.verifier.variable_versions, self.verifier.unrolling_depth)
            self.converter.convert_ssa_to_smt(ssa_lines)
            smt_lines = self.converter.get_smt()  # Get SMT lines from converter

        

            self.solver = SMTSolver()
            result = self.solver.smt_solver(smt_lines)

            smt_output = "\n".join(smt_lines)


            self.smt_output.delete("1.0", tk.END)
            self.smt_output.insert(tk.END, smt_output)

            # Display solver result in smt_final_output
            smt_output = f"===== SMT Solver Result =====\nStatus: {result['status']}\n"
            if result['model']:
                smt_output += "\nModel (Variable Values):\n"
                for var, val in result['model'].items():
                    smt_output += f"  {var} = {val}\n"

            self.smt_final_output.delete("1.0", tk.END)
            self.smt_final_output.insert(tk.END, smt_output)  # Display result in smt_final_output

            # Display control flow graph after 5 seconds
            self.root.after(3000, self.display_control_flow_graph, program_code, ssa_lines)

    def display_control_flow_graph(self, original_code, ssa_code):

        # Get the screen width and height
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Calculate positions for the two windows
        original_x = 20  # Left side
        original_y = (screen_height - 500) // 2  # Centered vertically

        ssa_x = screen_width - 360  # Right side
        ssa_y = (screen_height - 500) // 2  # Centered vertically

        # Create a window for the original CFG
        original_graph_window = tk.Toplevel(self.root)
        original_graph_window.title("Original Control Flow Graph")
        original_graph_window.geometry(f"400x500+{original_x}+{original_y}")

        # Create a frame for scrolling in the original CFG window
        original_scroll_frame = tk.Frame(original_graph_window)
        original_scroll_frame.pack(fill=tk.BOTH, expand=True)

        # Create a vertical scrollbar for the original CFG
        original_scrollbar = tk.Scrollbar(original_scroll_frame)
        original_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a canvas for the original CFG
        original_canvas = tk.Canvas(original_scroll_frame, bg="#f0f0f0", yscrollcommand=original_scrollbar.set)
        original_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure scrollbar for the original CFG
        original_scrollbar.config(command=original_canvas.yview)

        # === ORIGINAL CODE CFG ===
        original_graph = graphviz.Digraph('OriginalCFG', format='png')
        original_graph.attr(rankdir='TB', size='4,4', dpi='150')

        node_counter = 0
        prev_node = None

        for line in original_code:
            line = line.strip()
            if not line:
                continue
            node_id = f"O{node_counter}"
            if "input" in line:
                original_graph.node(node_id, line)
            elif "if" in line or "while" in line:
                original_graph.node(node_id, line, shape="diamond")
            elif "output" in line or "assert" in line:  # Decrease size for assert nodes
                original_graph.node(node_id, line, shape="doublecircle", width='0.3', height='0.3')  # Adjusted size here
            else:
                original_graph.node(node_id, line, shape="ellipse")
            if prev_node:
                original_graph.edge(prev_node, node_id)
            prev_node = node_id
            node_counter += 1

        # Add final end node
        original_graph.node("Oend", "End", shape="circle")
        original_graph.edge(prev_node, "Oend")

        # Render original CFG
        original_graph.render('original_cfg_graph', cleanup=True)

        # Load and display original CFG image
        try:
            original_img = tk.PhotoImage(file='original_cfg_graph.png')
            original_canvas.create_image(0, 0, anchor=tk.NW, image=original_img)
            original_canvas.image = original_img  # Keep a reference to avoid garbage collection
            original_canvas.config(scrollregion=original_canvas.bbox("all"))  # Set scroll region
        except Exception as e:
            print(f"Error displaying original CFG image: {e}")

        # Create a window for the SSA CFG
        ssa_graph_window = tk.Toplevel(self.root)
        ssa_graph_window.title("SSA Control Flow Graph")
        ssa_graph_window.geometry(f"400x500+{ssa_x}+{ssa_y}")

        # Create a frame for scrolling in the SSA CFG window
        ssa_scroll_frame = tk.Frame(ssa_graph_window)
        ssa_scroll_frame.pack(fill=tk.BOTH, expand=True)

        # Create a vertical scrollbar for the SSA CFG
        ssa_scrollbar = tk.Scrollbar(ssa_scroll_frame)
        ssa_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Create a canvas for the SSA CFG
        ssa_canvas = tk.Canvas(ssa_scroll_frame, bg="#f0f0f0", yscrollcommand=ssa_scrollbar.set)
        ssa_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Configure scrollbar for the SSA CFG
        ssa_scrollbar.config(command=ssa_canvas.yview)

        # === SSA CODE CFG ===
        ssa_graph = graphviz.Digraph('SSACFG', format='png')
        ssa_graph.attr(rankdir='TB', size='6,6', dpi='150')

        node_counter = 0
        prev_node = None

        for line in ssa_code:
            line = line.strip()
            if not line:
                continue
            node_id = f"S{node_counter}"
            if line.startswith("φ"):
                ssa_graph.node(node_id, line, shape="diamond")
            else:
                ssa_graph.node(node_id, line, shape="ellipse")
            if prev_node:
                ssa_graph.edge(prev_node, node_id)
            prev_node = node_id
            node_counter += 1

        # Add final end node
        ssa_graph.node("Send", "End", shape="circle")
        ssa_graph.edge(prev_node, "Send")

        # Render SSA CFG
        ssa_graph.render('ssa_cfg_graph', cleanup=True)

        # Load and display SSA CFG image
        try:
            ssa_img = tk.PhotoImage(file='ssa_cfg_graph.png')
            ssa_canvas.create_image(0, 0, anchor=tk.NW, image=ssa_img)
            ssa_canvas.image = ssa_img  # Keep a reference to avoid garbage collection
            ssa_canvas.config(scrollregion=ssa_canvas.bbox("all"))  # Set scroll region
        except Exception as e:
            print(f"Error displaying SSA CFG image: {e}")



if __name__ == "__main__":
    root = tk.Tk()
    root.state('zoomed')
    app = SSAAnalyzerUI(root)
    root.mainloop()
