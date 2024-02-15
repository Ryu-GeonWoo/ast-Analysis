import subprocess

def run_build_cfg(cfg_path, input_file_path, output_file_path):
    command = ["python", cfg_path, input_file_path, output_file_path]
    try:
        subprocess.run(command, check=True)
        print(f"{cfg_path} analysis completed. Output saved to {output_file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Error running {cfg_path}: {e}")

def run_cfg():
    cfg_path = 'Config/build_cfg.py'  # build_cfg.py
    input_path = 'Database/ast.json'
    output_path = 'Database/flow_test.json'

    run_build_cfg(cfg_path, input_path, output_path)
