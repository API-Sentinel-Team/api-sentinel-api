data "aws_iam_policy_document" "archive_access" {
  statement {
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ]
    resources = [
      aws_s3_bucket.archive.arn,
      "${aws_s3_bucket.archive.arn}/*"
    ]
  }
}

resource "aws_iam_policy" "archive_access" {
  name   = "${var.cluster_name}-archive-access"
  policy = data.aws_iam_policy_document.archive_access.json
}
