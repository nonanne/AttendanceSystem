import depthai as dai
import numpy as np
import cv2
import tensorflow as tf

# TensorFlowモデルのロード
interpreter = tf.lite.Interpreter(model_path="C:/Users/egna9/.City Master/detect.tflite")
interpreter.allocate_tensors()

input_details = interpreter.get_input_details()
output_details = interpreter.get_output_details()

# 入力テンソルの形状を取得
input_shape = input_details[0]['shape']

# Create pipeline
pipeline = dai.Pipeline()
pipeline.setXLinkChunkSize(0)

# Define source and output
camRgb = pipeline.create(dai.node.ColorCamera)
camRgb.setFps(60)
camRgb.setResolution(dai.ColorCameraProperties.SensorResolution.THE_1080_P)

xout = pipeline.create(dai.node.XLinkOut)
xout.setStreamName("out")
camRgb.isp.link(xout.input)

# Connect to device and start pipeline
with dai.Device(pipeline) as device:
    print(device.getUsbSpeed())
    q = device.getOutputQueue(name="out")
    diffs = np.array([])

    while True:
        imgFrame = q.get()
        frame = imgFrame.getCvFrame()

        # TensorFlow Liteモデルでの推論
        input_data = cv2.resize(frame, (300, 300))
        input_data = np.expand_dims(input_data, axis=0)
        input_data = input_data.astype(np.uint8)  # 正規化

        interpreter.set_tensor(input_details[0]['index'], input_data)
        interpreter.invoke()

        # 結果の取得
        boxes = interpreter.get_tensor(output_details[0]['index'])
        classes = interpreter.get_tensor(output_details[1]['index'])
        scores = interpreter.get_tensor(output_details[2]['index'])

        # 検出されたオブジェクトを描画
        for i in range(len(scores[0])):
            if scores[0][i] > 0.5:  # 信頼度が0.5以上のオブジェクトのみを描画
                ymin, xmin, ymax, xmax = boxes[0][i]
                xmin = int(xmin * frame.shape[1])
                xmax = int(xmax * frame.shape[1])
                ymin = int(ymin * frame.shape[0])
                ymax = int(ymax * frame.shape[0])
                cv2.rectangle(frame, (xmin, ymin), (xmax, ymax), (0, 255, 0), 2)
                label = f"{int(classes[0][i])}: {int(scores[0][i] * 100)}%"
                cv2.putText(frame, label, (xmin, ymin - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)

        # Latency in milliseconds
        latencyMs = (dai.Clock.now() - imgFrame.getTimestamp()).total_seconds() * 1000
        diffs = np.append(diffs, latencyMs)
        print('Latency: {:.2f} ms, Average latency: {:.2f} ms, Std: {:.2f}'.format(latencyMs, np.average(diffs), np.std(diffs)))

        # Display the frame
        cv2.imshow('frame', frame)
        if cv2.waitKey(1) == ord('q'):
            break

cv2.destroyAllWindows()
