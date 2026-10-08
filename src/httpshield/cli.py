import argparse

from .analyzer import audit
from .reporter import write_csv, write_json


def build_parser():
    parser = argparse.ArgumentParser(
        prog="httpshield",
        description="Defensive HTTP security header and cookie analyzer.",
    )
    parser.add_argument("url", help="Absolute http:// or https:// URL to analyze.")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", metavar="PATH", help="Write a JSON report.")
    parser.add_argument("--csv", metavar="PATH", help="Write check results as CSV.")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal findings.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = audit(args.url, args.timeout)

    if args.json:
        write_json(report, args.json)
    if args.csv:
        write_csv(report, args.csv)

    if "error" in report:
        if not args.quiet:
            print(f"HTTPShield ERROR: {report['error']}")
        return 2

    if not args.quiet:
        print("HTTPShield Security Report")
        print("─" * 60)
        print(f"Target:       {report['target']}")
        print(f"Final URL:    {report['final_url']}")
        print(f"HTTP Status:  {report['status_code']}")
        print(f"Score:        {report['score']}/100 ({report['grade']})")
        print(f"Redirects:    {len(report['redirects'])}")
        print()
        for check in report["checks"]:
            print(f"[{check['status']:<13}] {check['severity']:<8} {check['title']} — {check['score']}/100")
            print(f"  Evidence: {check['evidence']}")
            print(f"  Fix:      {check['remediation']}")
            print()

    return 1 if report["summary"]["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
