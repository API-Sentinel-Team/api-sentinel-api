output "eks_cluster_name" {
  value = module.eks.cluster_name
}

output "rds_endpoint" {
  value = module.rds.db_instance_endpoint
}

output "msk_bootstrap_brokers" {
  value = aws_msk_cluster.kafka.bootstrap_brokers
}

output "redis_primary_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "archive_bucket" {
  value = aws_s3_bucket.archive.bucket
}

output "archive_policy_arn" {
  value = aws_iam_policy.archive_access.arn
}
