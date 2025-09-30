#!/usr/bin/python3

import subprocess
import re

from time import sleep
from config_auto import IV, key, loop_count, sleep_time,\
     fast_enc_bin, fast_dec_bin, norm_enc_bin, norm_dec_bin, \
     fast_enc_result, fast_dec_result, norm_enc_result, norm_dec_result


enc_binaries = [
        (fast_enc_bin, IV, key),
        (norm_enc_bin, IV, key),
        ]

dec_binaries = [
        (fast_dec_bin, IV),
        (norm_dec_bin, IV),
        ]

pattern = re.compile(r"Execution time:\s*([0-9.]+)\s*seconds")


def calc_improvement(fast, normal):
    print(f"## Compare Execution Time {fast} <-> {normal}")

    if fast is None or normal is None:
        return None
    return normal - fast , ((normal - fast) / fast) * 100


def check_contents(cmp1, cmp2):
    print(f"## Compare file context {cmp1} <-> {cmp2}")
    context1 = b""
    context2 = b""
    
    with open(cmp1, "rb") as f1:
        context1 = f1.read();

    with open(cmp2, "rb") as f2:
        context2 = f2.read();


    if context1 == context2:
        print(f"  - Eqaul between {cmp1} and {cmp2}...")
    else:
        print(f"  - Different between {cmp1} and {cmp2}!!!")

def compare_main():
    execution_times = []

    for i in range(len(enc_binaries)):
        enc_info = enc_binaries[i];
        dec_info = dec_binaries[i];
        try:
            result = subprocess.run([enc_info[0], enc_info[1], enc_info[2]], capture_output=True, text=True)
            match = pattern.search(result.stdout)
            if match:
                time = float(match.group(1))
                execution_times.append(time)
                print(f"{enc_info[0]} Execution Time: {time:.6f}...")
            else:
                print(f"{enc_info[0]} Can not find Execution Time!!!")
                execution_times.append(None)

            result = subprocess.run([dec_info[0], dec_info[1]], capture_output=True, text=True)
            match = pattern.search(result.stdout)
            if match:
                time = float(match.group(1))
                execution_times.append(time)
                print(f"{dec_info[0]} Execution Time: {time:.6f}...")
            else:
                print(f"{dec_info[0]} Can not find Execution Time!!!")
                execution_times.append(None)

        except subprocess.CalledProcessError as e:
            print(f"Error Occur: {e}!!!")
            execution_times.append(None)

    if len(execution_times) > 3:
        print(f"\n### Compare result")
        check_contents(fast_enc_result, norm_enc_result)
        check_contents(fast_dec_result, norm_dec_result)
        print()
        imp_sec_1_3, imp_1_3 = calc_improvement(execution_times[0], execution_times[2])

        if imp_1_3 is not None:
            print(f"  - Encryption performance improvement: {imp_1_3:.2f}%")
        else:
            print("  - Can not compare execution time")

        imp_sec_2_4, imp_2_4 = calc_improvement(execution_times[1], execution_times[3])
        if imp_2_4 is not None:
            print(f"  - Decnryption performance improvement: {imp_2_4:.2f}%")
        else:
            print("  - Can not compare execution time")


    return imp_1_3, imp_sec_1_3, imp_2_4, imp_sec_2_4
        
        
if __name__=="__main__":
    enc_res_min, enc_res_max, enc_res_avg, enc_sec_avg, enc_bad_perf_cnt = 100, 0, 0, 0, 0
    dec_res_min, dec_res_max, dec_res_avg, dec_sec_avg, dec_bad_perf_cnt = 100, 0, 0, 0, 0
    perf_enc_res = []
    perf_dec_res = []
    print("Performance Compare Loop: ", loop_count)

    for idx in range(1, loop_count + 1):
        print(f"###### Loop Count: [{idx}]")
        enc_res, enc_sec, dec_res, dec_sec = compare_main()
        if enc_res is None or dec_res is None:
            print("Result is None Skip this loop...")
            continue
        if enc_res < 0:
            enc_bad_perf_cnt += 1
        enc_res_min = enc_res if enc_res < enc_res_min else enc_res_min
        enc_res_max = enc_res if enc_res > enc_res_max else enc_res_max
        enc_res_avg += enc_res
        enc_sec_avg += enc_sec
        perf_enc_res.append(enc_res)

        if dec_res < 0:
            dec_bad_perf_cnt += 1
        dec_res_min = dec_res if dec_res < dec_res_min else dec_res_min
        dec_res_max = dec_res if dec_res > dec_res_max else dec_res_max
        dec_res_avg += dec_res
        dec_sec_avg += dec_sec
        perf_dec_res.append(dec_res)

        print()
        sleep(sleep_time)
    
    enc_res_avg /= loop_count
    dec_res_avg /= loop_count
    enc_sec_avg /= loop_count
    dec_sec_avg /= loop_count

    print("------- Summary ------")
    print("Loop Count: ", loop_count)
    print("[ENCRYPT SUMMARY]")
    print(f"Avg improvement sec: {enc_sec_avg:.4f}s")
    print(f"Avg improvement rate: {enc_res_avg:.2f}%")
    print(f"Max improvement rate: {enc_res_max:.2f}%")
    print(f"Min improvement rate: {enc_res_min:.2f}%")
    print(f"Bad performance rate: {enc_bad_perf_cnt/loop_count*100:.2f}% [{enc_bad_perf_cnt} / {loop_count}]")

    print("[DECRYPT SUMMARY]")
    print(f"Avg improvement sec: {dec_sec_avg:.4f}s")
    print(f"Avg improvement rate: {dec_res_avg:.2f}%")
    print(f"Max improvement rate: {dec_res_max:.2f}%")
    print(f"Min improvement rate: {dec_res_min:.2f}%")
    print(f"Bad performance rate: {dec_bad_perf_cnt/loop_count*100:.2f}% [{dec_bad_perf_cnt} / {loop_count}]")

    print()
    print("Total performance rate ([LOOP] ENC | DEC)")
    for idx in range(len(perf_enc_res)):
        print(f"[Loop: {idx + 1}] {perf_enc_res[idx]:.2f}% | {perf_dec_res[idx]:.2f}%")
    print()
    print()

