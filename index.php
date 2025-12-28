<?php
// Define the path to the yt-dlp executable on Windows. Adjust this to your actual path.
// Download yt-dlp.exe from https://github.com/yt-dlp/yt-dlp/releases and place it in a known directory.
define('YT_DLP', 'C:\downloader-yt\yt-dlp.exe'); // Example: Change to your actual path, e.g., 'C:\\Users\\YourName\\Downloads\\yt-dlp.exe'

// Get the YouTube video ID from the query parameter (e.g., ?video_id=VIDEO_ID_HERE)
if (isset($_GET['video_id']) && preg_match('/^[0-9A-Za-z_-]{11}$/', $_GET['video_id'])) {
    $youtube_url = 'https://www.youtube.com/watch?v=' . $_GET['video_id'];
} else {
    die('Invalid or missing video ID. Usage: ?video_id=VIDEO_ID');
}

/**
 * Fetches the direct URL of the YouTube video using yt-dlp.
 * Uses '-f best -g' to get the best quality direct URL.
 */
function getDirectUrl($youtube_url) {
    $command = YT_DLP . ' -f best -g ' . escapeshellarg($youtube_url);
    $direct_url = shell_exec($command);
    // Trim any whitespace or newlines
    $direct_url = trim($direct_url);
    if (empty($direct_url)) {
        die('Failed to retrieve direct URL. Ensure yt-dlp.exe is installed and the path is correct.');
    }
    return $direct_url;
}

// Fetch the direct URL
$direct_url = getDirectUrl($youtube_url);

// Output the HTML5 video player with the direct URL
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Custom YouTube Video Player (Windows)</title>
    <style>
        /* Basic styling for the player */
        body { font-family: Arial, sans-serif; text-align: center; }
        video { max-width: 100%; height: auto; border: 1px solid #ccc; }
    </style>
</head>
<body>
    <h1>Custom Embedded YouTube Video Player</h1>
    <video controls width="640" height="360">
        <source src="<?php echo htmlspecialchars($direct_url); ?>" type="video/mp4">
        Your browser does not support the video tag.
    </video>
    <p>This is a custom HTML5 player embedding the video directly via yt-dlp fetched URL.</p>
    <p><strong>Note:</strong> Direct URLs may expire after a short time. For production use, consider caching or refreshing dynamically.</p>
</body>
</html>