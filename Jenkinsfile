pipeline {
    agent any 
    environment {
        IMAGE_NAME = "registry.yamong.dev/yamong_ebpf"
    }
    stages {
        stage('docker image build and tag') {
            agent any
            steps {
                script {
                    def imageTags = generateImageTags(env.BRANCH_NAME)
                    // Store the tags in environment variables for later use
                    env.IMAGE_TAG_WITH_HASH = imageTags.imageTagWithHash
                    env.IMAGE_TAG_BRANCH_ONLY = imageTags.imageTagBranchOnly
                    sh "git submodule update --init --recursive"
                    sh "docker build -t ${env.IMAGE_NAME}:${env.IMAGE_TAG_WITH_HASH} ."
                    sh "docker tag ${env.IMAGE_NAME}:${env.IMAGE_TAG_WITH_HASH} ${env.IMAGE_NAME}:${env.IMAGE_TAG_BRANCH_ONLY}"
                    sh "docker tag ${env.IMAGE_NAME}:${env.IMAGE_TAG_WITH_HASH} ${env.IMAGE_NAME}:latest"
                }
            }
        }
        stage('docker image push') {
            agent any
            steps {
                script {
                    // Use the stored environment variables
                    sh "docker push ${env.IMAGE_NAME}:${env.IMAGE_TAG_WITH_HASH}"
                    sh "docker push ${env.IMAGE_NAME}:${env.IMAGE_TAG_BRANCH_ONLY}"
                    sh "docker push ${env.IMAGE_NAME}:latest"
                }
            }
        }
    }
    post {
        success {
            script {
                // No need to call generateImageTags again
                withCredentials([string(credentialsId: 'Discord-Webhook', variable: 'DISCORD')]) {
                    discordSend description: """
                    Title : ${currentBuild.displayName}
                    Result : ${currentBuild.result}
                    Build Duration : ${currentBuild.duration / 1000}s
                    image : ${env.IMAGE_NAME}:${env.IMAGE_TAG_WITH_HASH}
                    image : ${env.IMAGE_NAME}:${env.IMAGE_TAG_BRANCH_ONLY}
                    image : ${env.IMAGE_NAME}:latest
                    """,
                    link: env.BUILD_URL, result: currentBuild.currentResult, 
                    title: "${env.JOB_NAME} : ${currentBuild.displayName} Success", 
                    webhookURL: "${DISCORD}"
                }
            }
        }
        failure {
            script {
                withCredentials([string(credentialsId: 'Discord-Webhook', variable: 'DISCORD')]) {
                    discordSend description: """
                    Title : ${currentBuild.displayName}
                    Result : ${currentBuild.result}
                    Build Duration : ${currentBuild.duration / 1000}s
                    """,
                    link: env.BUILD_URL, result: currentBuild.currentResult, 
                    title: "${env.JOB_NAME} : ${currentBuild.displayName} Failed", 
                    webhookURL: "${DISCORD}"
                }
            }
        }
    }
}

def generateImageTags(branchName) {
    def sanitizedBranchName = branchName.replaceAll(/[^a-zA-Z0-9_\-\.]/, '_')
    def commitHash = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
    return [
        sanitizedBranchName: sanitizedBranchName,
        commitHash: commitHash,
        imageTagWithHash: "${sanitizedBranchName}-${commitHash}",
        imageTagBranchOnly: sanitizedBranchName
    ]
}
