import tpm2/serialization

var x = newStaticByteBuffer()
serialize(4'u8, x)

echo x.readBytes(1)
