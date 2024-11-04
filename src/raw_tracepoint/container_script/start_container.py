import docker
import sys

def start_containers(image_name, container_prefix, count):
    client = docker.from_env()
    
    for i in range(1, count + 1):
        container_name = f"{container_prefix}_{i}"
        try:
            container = client.containers.run(
                image=image_name,
                name=container_name,
                detach=True
            )
            print(f"Started container: {container.name} (ID: {container.id})")
        except docker.errors.APIError as e:
            print(f"Failed to start container {container_name}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python start_containers.py <count>")
        sys.exit(1)
    
    image_name = "ubuntu-sleep"
    container_prefix = "sleep_con"
    try:
        count = int(sys.argv[1])
    except ValueError:
        print("Count must be an integer.")
        sys.exit(1)
    
    start_containers(image_name, container_prefix, count)

