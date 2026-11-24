from integrated_monitor import start_integrated_monitor


def main():
    print("=" * 70)
    print("SECURE FILE TRANSFER MONITORING SYSTEM")
    print("=" * 70)
    print("Starting monitoring system...")
    print("=" * 70)

    try:
        start_integrated_monitor()

    except KeyboardInterrupt:
        print("\nMonitoring system stopped by user.")

    except Exception as error:
        print(f"\nMonitoring system error: {error}")


if __name__ == "__main__":
    main()