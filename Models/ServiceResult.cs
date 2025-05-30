namespace JwtAuth.Models
{
    public class ServiceResult
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class ServiceResult<T> : ServiceResult
    {
        public T? Data { get; set; }
    }
}
