import serial
import struct
import time

# 配置串口（根据你的设备调整）
SERIAL_PORT = '/dev/ttyACM1'  # Linux 示例，Windows 可能是 'COM3'
BAUD_RATE = 38400

def send_safe_input():
    # 打开串口
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    time.sleep(60)  # 等待 Arduino 重启并准备好
    print("Arduino ready")
    while True:
        # 等待 Arduino 发送 'A'（请求输入）
        if ser.read(1) == b'A':
            # 示例 1：安全的输入 "test"（长度 4）
            response_length = 4
            data = b"test"
            while True:
                time.sleep(3)
                # 发送 4 字节的 response_length（小端序）
                ser.write(struct.pack('<I', response_length))
                # 发送数据
                ser.write(data)
                print(f"Sent to Arduino: {data}")
                output = ser.read(1)
                if output:
                    print(f"Received from Arduino: {output}")

            # 可选：读取输出（例如 stack_array[3]）
            output = ser.read(1)
            if output:
                print(f"Received from Arduino: {output}")

            time.sleep(0.1)  # 短暂等待，避免过快循环

        # 示例 2：安全的输入 "bug!x"（长度 5）
        elif False:  # 切换到这个条件测试 "bug!x"
            response_length = 5
            data = b"bug!x"

            ser.write(struct.pack('<I', response_length))
            ser.write(data)

            output = ser.read(1)
            if output:
                print(f"Received from Arduino: {output}")

            time.sleep(0.1)

if __name__ == "__main__":
    try:
        send_safe_input()
    except KeyboardInterrupt:
        print("Stopped by user")
    except Exception as e:
        print(f"Error: {e}")