# Fuzzing Framework

## Overview

This project is a fuzzing framework that interacts with a target device via serial communication and GDB for debugging. It generates inputs, sends them to the target, monitors responses, and sets breakpoints based on definitions and uses parsed from a file.

## Project Structure

- `main.py`: Entry point of the application.
- `fuzzing/`: Core fuzzing logic.
- `communication/`: Handles serial and GDB communications.
- `utils/`: Utility functions.
- `config/`: Configuration settings.
- `logs/`: Directory to store log files.

## Setup

1. **Clone the Repository**

    ```bash
    git clone https://github.com/yourusername/your_project.git
    cd your_project
    ```

2. **Create a Virtual Environment**

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3. **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4. **Configuration**

    Modify the settings in `config/settings.py` as per your environment and requirements.

5. **Prepare Directories**

    Ensure that the `output/` and `seeds/` directories exist. Place your seed files in the `seeds/` directory.

6. **Run the Application**

    ```bash
    python main.py
    ```

## Usage

The application will:

1. Initialize the fuzzing corpus from seed files.
2. Connect to GDB and set breakpoints based on definitions and uses.
3. Generate and send test cases to the target device via serial communication.
4. Monitor responses and adjust fuzzing strategies accordingly.

## Logging

Logs are stored in the `logs/` directory. You can adjust the logging level in `config/settings.py`.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

[MIT License](LICENSE)
