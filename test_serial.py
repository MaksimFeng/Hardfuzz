import serial

ser = serial.Serial('/dev/ttyACM1', 38400, timeout=1)
while True:
    data = ser.read(1)
    if data:
        print(f"Received: {data}")
