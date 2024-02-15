import datetime
import json


def log_error(file_path, error):
    error_info = {
        "file_path": file_path,
        "error": str(error),
        "timestamp": datetime.datetime.now().isoformat()
    }

    try:
        with open('error_log.json', 'a') as log_file:
            json.dump(error_info, log_file)
            log_file.write('\n')
    except IOError as e:
        print(f"Failed to log error: {e}")
