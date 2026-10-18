import { describe, expect, it } from "vitest";
import { basename, eventCodeLabel, ratio, score, shortGuid } from "./format";

describe("format helpers", () => {
  it("formats signed log-odds without rounding the sign away", () => {
    expect(score("7.365072237577558260033422944")).toBe("+7.37");
    expect(score("0")).toBe("+0.00");
    expect(score("-3.17", 1)).toBe("-3.2");
    expect(score(null)).toBe("—");
  });

  it("renders undefined metrics as 'undefined', never as zero", () => {
    expect(ratio(null)).toBe("undefined");
    expect(ratio("0.9885057471264367816091954023")).toBe("0.989");
  });

  it("shortens Sysmon GUIDs and Windows paths", () => {
    expect(shortGuid("{0000AAAA-8BD2-6A96-6708-000000001B00}")).toBe("8BD2-6A96-6708");
    expect(basename("C:\\Windows\\System32\\fodhelper.exe")).toBe("fodhelper.exe");
    expect(eventCodeLabel("13")).toBe("13 RegistryValueSet");
    expect(eventCodeLabel("99")).toBe("EID 99");
  });
});
