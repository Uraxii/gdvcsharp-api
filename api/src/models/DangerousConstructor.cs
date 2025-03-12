namespace GdvCsharp.API.Models
{
    public class DangerousConstructor
    {
        public readonly string defaultPrefs = @"{default: true}";

        public string FileName { get; set; }
        public string Content { get; set; }

        public DangerousConstructor()
        {
        }

        public DangerousConstructor(string filePath)
        {
            FileName = filePath;

            if (!File.Exists(filePath))
            {
                File.WriteAllText(filePath, defaultPrefs);
            }

            Content = File.ReadAllText(filePath);
        }
    }
}
