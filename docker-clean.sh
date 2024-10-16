echo "Cleaning up Docker containers..."

# Stop all running Docker containers
docker stop $(docker ps -q)

# Remove all Docker containers
docker rm $(docker ps -a -q)

# Remove all Docker images (optional)
# Uncomment the next line if you also want to remove all Docker images
# docker rmi $(docker images -q)

echo "Docker containers cleaned up."