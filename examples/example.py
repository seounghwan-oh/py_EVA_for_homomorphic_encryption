# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

from eva import EvaProgram, Input, Output, evaluate, save, load
from eva.ckks import CKKSCompiler
from eva.seal import generate_keys
from eva.metric import valuation_mse
from random import uniform
import numpy as np

poly = EvaProgram("Polynomial", vec_size=(10**5))
with poly:
    a = Input("a")
    b = Input("b")
    Output("result", 5*(a**5)*(b**4))

poly.set_output_ranges(128)
poly.set_input_scales(128)

compiler = CKKSCompiler()
poly, params, signature = compiler.compile(poly)

public_ctx, secret_ctx = generate_keys(params)

inputs = {
    "a": [uniform(1000, 10000) for _ in range(signature.vec_size)],
    "b": [uniform(0.001, 0.01) for _ in range(signature.vec_size)]
}
encInputs = public_ctx.encrypt(inputs, signature)

encOutputs = public_ctx.execute(poly, encInputs)

print("encOutputs", encOutputs)

outputs = secret_ctx.decrypt(encOutputs, signature)

reference = evaluate(poly, inputs)

expected = reference["result"]
got = outputs["result"]
error_rate = []
for i in range(signature.vec_size):
    error_rate.append((abs(expected[i]-got[i])/abs(expected[i]))*100)
error_rates = {}
error_rates["result"] = error_rate

print("inputs", inputs)
print("Origin outputs", reference)
print("Encrypted outputs", outputs)
print("Error Rates", error_rates)
#print("MSE", valuation_mse(outputs, reference))

file = open("ckks_mult_example.txt", "w")
for i in range(signature.vec_size):
    if error_rates["result"][i] < 0.0001:
        result = "True"
        data = "\"a^5\": " + str(inputs["a"][i]) + " " \
               + "\"b^4\": " + str(inputs["b"][i]) + " " \
               + "\"Origin output\": " + str(reference["result"][i]) + " " \
               + "\"Encrypted output\": " + str(outputs["result"][i]) + " " \
               + "\"Error Rate\": " + str(result)

        file.write(data + "\n")
    else:
        result = "False"
        data = "\"a^5\": " + str(inputs["a"][i]) + " " \
               + "\"b^4\": " + str(inputs["b"][i]) + " " \
               + "\"Origin output\": " + str(reference["result"][i]) + " " \
               + "\"Encrypted output\": " + str(outputs["result"][i]) + " " \
               + "\"Error Rate\": " + str(result)

        file.write(data + "\n")

file.close()
print("Complete")
