"""
E2E validation script for Aegis Core.
Can be run on the host or the Hyper-V target VM.
Verifies telemetry from the live system pipeline.
"""
import sys
import time
from pathlib import Path

# Add project root to path so we can import aegis_core
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from aegis_core.engine import MonitoringConfig, MonitoringEngine
from aegis_core.models import Environment


def run_e2e() -> int:
    print("=== Aegis Core E2E Validation ===")
    
    config = MonitoringConfig(
        environment=Environment.DEVELOPMENT,
        data_directory=Path("./e2e_data"),
        interval_seconds=2.0,
    )
    
    print("Initializing full auto-discovered pipeline...")
    try:
        engine = MonitoringEngine.build_from_capability(
            config=config,
            watch_roots=[Path(".")],  # Watch current dir for file events
            enable_auth=True
        )
    except Exception as e:
        print(f"Failed to build engine: {e}")
        return 1

    print("Pipeline built successfully.")
    
    print("Starting collection for 10 seconds...")
    try:
        engine.start()
        engine.run_for(10.0)
    except Exception as e:
        print(f"Failed during run: {e}")
        return 1
        
    print("Run completed.")
    
    from aegis_core.storage import EvidenceStore
    store = EvidenceStore(config.data_directory / "evidence.sqlite3")
    
    total_events = store.count_events()
    findings = store.get_findings()
    chain_valid = store.verify_chain()
    
    print(f"\nResults:")
    print(f"  Total events collected: {total_events}")
    print(f"  Findings generated: {len(findings)}")
    print(f"  Hash chain valid: {chain_valid}")
    
    # Check what kinds of events we got
    kinds = ["process", "network", "file", "authentication", "health"]
    print("\nEvent counts by kind:")
    for kind in kinds:
        count = store.count_events(kinds=[kind])
        print(f"  {kind}: {count}")

    if not chain_valid:
        print("ERROR: Hash chain is invalid!")
        return 1
        
    if total_events == 0:
        print("ERROR: No events collected!")
        return 1
        
    print("\nSUCCESS: E2E Validation passed.")
    return 0

if __name__ == "__main__":
    sys.exit(run_e2e())
