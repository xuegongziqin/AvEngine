import sys
import time
import xml.etree.ElementTree as ET
import win32evtlog
import win32api

CHANNEL = "Microsoft-Windows-Sysmon/Operational"

def close_handle(h):
    if h:
        try:
            win32api.CloseHandle(h)
        except:
            pass

def read_events():
    query_handle = win32evtlog.EvtQuery(
        Path=CHANNEL,
        Query="*",
        Flags=win32evtlog.EvtQueryChannelPath,
    )
    last_id = 0
    try:
        while True:
            try:
                events = win32evtlog.EvtNext(query_handle, 10, 100, 0)
            except Exception as e:
                print(f"EvtNext error: {e}")
                break
            for evt in events:
                try:
                    xml = win32evtlog.EvtRender(evt, win32evtlog.EvtRenderEventXml)
                    root = ET.fromstring(xml)
                    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
                    sys_node = root.find(f"{ns}System")
                    eid_node = sys_node.find(f"{ns}EventID")
                    record_node = sys_node.find(f"{ns}EventRecordID")
                    if eid_node is not None and record_node is not None:
                        eid = int(eid_node.text)
                        rid = int(record_node.text)
                        if rid > last_id:
                            last_id = rid
                            time_node = sys_node.find(f"{ns}TimeCreated")
                            time_str = time_node.attrib.get("SystemTime", "")
                            print(f"[{time_str}] EventID={eid}")
                except Exception as e:
                    print(f"Parse error: {e}")
                finally:
                    close_handle(evt)
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        close_handle(query_handle)

if __name__ == "__main__":
    print("Listening for Sysmon events... (Ctrl+C to stop)")
    read_events()
