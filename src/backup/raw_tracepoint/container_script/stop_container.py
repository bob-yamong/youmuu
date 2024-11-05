import docker
import sys

def stop_containers(container_prefix):
    client = docker.from_env()
    
    try:
        containers = client.containers.list(all=True, filters={"name": container_prefix})
        if not containers:
            print(f"No containers found with prefix '{container_prefix}'.")
            return
        
        for container in containers:
            try:
                container.stop()
                container.remove()
                print(f"Stopped and removed container: {container.name} (ID: {container.id})")
            except docker.errors.APIError as e:
                print(f"Failed to stop/remove container {container.name}: {e}")
    except docker.errors.APIError as e:
        print(f"Docker API error: {e}")

if __name__ == "__main__":
    container_prefix = "sleep_con"
    stop_containers(container_prefix)

