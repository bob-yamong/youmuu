pipeline {
    agent none 
    stages {
        stage('docker image build and tag') {
            agent any
            steps {
                script {
                    def imageName = "registry.yamong.dev/yamong_ebpf"
                    def sanitizedBranchName = env.BRANCH_NAME.replaceAll(/[^a-zA-Z0-9_\-\.]/, '_')
                    def commitHash = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    def imageTagWithHash = "${sanitizedBranchName}-${commitHash}"
                    def imageTagBranchOnly = "${sanitizedBranchName}"
                    sh "git submodule update --init --recursive"
                    sh "docker build -t ${imageName}:${imageTagWithHash} ."

                    sh "docker tag ${imageName}:${imageTagWithHash} ${imageName}:${imageTagBranchOnly}"
                    sh "docker tag ${imageName}:${imageTagWithHash} ${imageName}:latest"
                }
            }
        }
        stage('docker image push') {
            agent any
            steps {
                script {
                    def imageName = "registry.yamong.dev/yamong_ebpf"
                    def sanitizedBranchName = env.BRANCH_NAME.replaceAll(/[^a-zA-Z0-9_\-\.]/, '_')
                    def commitHash = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    def imageTagWithHash = "${sanitizedBranchName}-${commitHash}"
                    def imageTagBranchOnly = "${sanitizedBranchName}"

                    sh "docker push ${imageName}:${imageTagWithHash}"
                    sh "docker push ${imageName}:${imageTagBranchOnly}"
                    sh "docker push ${imageName}:latest"
                }
            }
        }
    }
}
