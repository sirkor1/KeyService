using System.Buffers.Binary;
using System.IO.Compression;
using ZXing;
using ZXing.Common;

/// <summary>
/// Проверка PNG с QR-кодом без System.Drawing: разбор заголовка, распаковка пикселей и декодирование ZXing.Net.
/// Декодер понимает только то, что выпускает QRCoder (PngByteQRCode): фильтр 0 и серый/палитровый/RGB без чересстрочности.
/// Остальное — исключение, чтобы смена формата картинки не превратилась в молчаливый «не декодировано».
/// </summary>
static class QrCheck
{
    public sealed record Header(int Width, int Height, int BitDepth, int ColorType);

    public static Header ReadHeader(byte[] png)
    {
        // сигнатура (8) + длина (4) + «IHDR» (4) + данные
        var width = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16, 4));
        var height = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20, 4));
        return new Header(width, height, png[24], png[25]);
    }

    /// <summary>Содержимое QR-кода или null, если декодер его не нашёл.</summary>
    public static string? Decode(byte[] png)
    {
        var header = ReadHeader(png);
        if (png[28] != 0) throw new NotSupportedException("Чересстрочный PNG.");

        byte[]? palette = null;
        using var idat = new MemoryStream();
        for (var offset = 8; offset + 8 <= png.Length;)
        {
            var length = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(offset, 4));
            var type = System.Text.Encoding.ASCII.GetString(png, offset + 4, 4);
            if (type == "IDAT") idat.Write(png, offset + 8, length);
            if (type == "PLTE") palette = png.AsSpan(offset + 8, length).ToArray();
            offset += 12 + length;
        }

        idat.Position = 0;
        using var raw = new MemoryStream();
        using (var zlib = new ZLibStream(idat, CompressionMode.Decompress)) zlib.CopyTo(raw);
        var data = raw.ToArray();

        var channels = header.ColorType switch { 0 => 1, 2 => 3, 3 => 1, _ => throw new NotSupportedException("Тип цвета " + header.ColorType) };
        var bitsPerPixel = channels * header.BitDepth;
        var stride = (header.Width * bitsPerPixel + 7) / 8;
        if (data.Length != (stride + 1) * header.Height) throw new InvalidDataException("Размер распакованных данных не сходится.");

        var luminance = new byte[header.Width * header.Height];
        for (var y = 0; y < header.Height; y++)
        {
            var row = y * (stride + 1);
            if (data[row] != 0) throw new NotSupportedException("Фильтр строки " + data[row]);
            for (var x = 0; x < header.Width; x++)
            {
                byte value;
                if (header.ColorType == 2)
                {
                    var p = row + 1 + x * 3;
                    value = (byte)((data[p] + data[p + 1] + data[p + 2]) / 3);
                }
                else
                {
                    var bit = x * header.BitDepth;
                    var sample = header.BitDepth == 8
                        ? data[row + 1 + x]
                        : (data[row + 1 + bit / 8] >> (8 - header.BitDepth - bit % 8)) & ((1 << header.BitDepth) - 1);
                    if (header.ColorType == 3)
                    {
                        var p = sample * 3;
                        value = (byte)((palette![p] + palette[p + 1] + palette[p + 2]) / 3);
                    }
                    else
                    {
                        value = header.BitDepth == 8 ? (byte)sample : (byte)(sample * 255 / ((1 << header.BitDepth) - 1));
                    }
                }
                luminance[y * header.Width + x] = value;
            }
        }

        var reader = new BarcodeReaderGeneric
        {
            AutoRotate = false,
            Options = new DecodingOptions { PossibleFormats = [BarcodeFormat.QR_CODE], TryHarder = true },
        };
        return reader.Decode(new RGBLuminanceSource(luminance, header.Width, header.Height, RGBLuminanceSource.BitmapFormat.Gray8))?.Text;
    }
}
