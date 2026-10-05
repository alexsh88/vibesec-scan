type Comment = { authorName: string; html: string };

export function CommentView({ comment }: { comment: Comment }) {
  return (
    <div className="comment">
      <strong>{comment.authorName}</strong>
      <div dangerouslySetInnerHTML={{ __html: comment.html }} />
    </div>
  );
}

export function CommentAuthor({ comment }: { comment: Comment }) {
  return <span>{comment.authorName}</span>;
}
