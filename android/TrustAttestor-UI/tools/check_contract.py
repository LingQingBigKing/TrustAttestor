"""Check frozen UI data/report contracts against a TA checkout; never write files."""
import argparse
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True)
    args = parser.parse_args()
    ui = Path(__file__).resolve().parents[1] / 'app/src/preview/java/com/lingqing/trustattestor'
    target = args.target.resolve() / 'app/src/main/java/com/lingqing/trustattestor'
    contracts = [('UiModels.kt', 'MainViewModel.kt', 'enum class ScanState'),
                 ('FindingModels.kt', 'TrustAttestorNativeBridge.kt', 'enum class FindingStatus'),
                 ('ForensicReportCodec.kt', 'ForensicReportCodec.kt', 'object ForensicReportCodec')]
    changed = []
    for local, original, marker in contracts:
        try:
            preview_text = (ui / local).read_text(encoding='utf-8-sig')
            target_text = (target / original).read_text(encoding='utf-8-sig')
            same = preview_text[preview_text.index(marker):].strip() == target_text[target_text.index(marker):].strip()
        except (OSError, ValueError) as error:
            print(f'Cannot compare {local}: {error}')
            changed.append(local)
            continue
        print(f'{"MATCH" if same else "CHANGED"}: {local} <- {original}')
        if not same:
            changed.append(local)
    if changed:
        print('Review contract changes in both projects; this check never copies backend code.')
    return 1 if changed else 0


if __name__ == '__main__':
    sys.exit(main())
