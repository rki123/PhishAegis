"""
Character-Level Deep Learning Model for URL Classification.
Converts raw URL strings into sequences of character indices,
then uses a CNN to learn structural patterns.
"""
import numpy as np
import os


# Fixed character vocabulary: every printable ASCII char gets an index
CHAR_VOCAB = {chr(i): i - 31 for i in range(32, 127)}  # space=1, '!'=2, ... '~'=95
VOCAB_SIZE = len(CHAR_VOCAB) + 2  # +1 for padding (0), +1 for unknown chars
MAX_URL_LEN = 200  # Truncate/pad all URLs to this length


def normalize_url(url):
    """
    Same normalization as extraction.py to fix data leakage.
    Strips http://, https://, www. prefixes.
    """
    clean = url.lower()
    if clean.startswith('https://'):
        clean = clean[8:]
    elif clean.startswith('http://'):
        clean = clean[7:]
    if clean.startswith('www.'):
        clean = clean[4:]
    return clean


def url_to_sequence(url, max_len=MAX_URL_LEN):
    """Convert a single URL string into a fixed-length integer sequence."""
    clean = normalize_url(url)
    seq = [CHAR_VOCAB.get(c, VOCAB_SIZE - 1) for c in clean[:max_len]]
    # Pad with zeros if shorter than max_len
    if len(seq) < max_len:
        seq += [0] * (max_len - len(seq))
    return seq


def urls_to_sequences(urls, max_len=MAX_URL_LEN):
    """Convert a list/Series of URLs into a 2D numpy array of shape (n, max_len)."""
    return np.array([url_to_sequence(u, max_len) for u in urls], dtype=np.int32)


def build_cnn_model(vocab_size=VOCAB_SIZE, max_len=MAX_URL_LEN):
    """
    Build a Character-Level CNN for binary URL classification.
    Architecture: Embedding -> Conv1D blocks -> GlobalMaxPool -> Dense -> Output
    """
    from tensorflow.keras import layers, models, regularizers

    inp = layers.Input(shape=(max_len,), dtype='int32')
    x = layers.Embedding(input_dim=vocab_size, output_dim=64, input_length=max_len)(inp)
    
    # Drop entire 1D feature maps to prevent overfitting to specific character positions
    x = layers.SpatialDropout1D(0.2)(x)

    # Three parallel convolution filter sizes to capture different n-gram patterns
    conv3 = layers.Conv1D(128, kernel_size=3, activation='relu', padding='same')(x)
    conv5 = layers.Conv1D(128, kernel_size=5, activation='relu', padding='same')(x)
    conv7 = layers.Conv1D(128, kernel_size=7, activation='relu', padding='same')(x)

    # Merge convolutions
    merged = layers.Concatenate()([conv3, conv5, conv7])
    merged = layers.BatchNormalization()(merged)
    merged = layers.GlobalMaxPooling1D()(merged)

    # Dense classification head with L2 regularization and high dropout
    x = layers.Dense(128, activation='relu', kernel_regularizer=regularizers.l2(0.01))(merged)
    x = layers.Dropout(0.5)(x)
    x = layers.Dense(64, activation='relu', kernel_regularizer=regularizers.l2(0.01))(x)
    x = layers.Dropout(0.3)(x)
    out = layers.Dense(1, activation='sigmoid')(x)

    model = models.Model(inputs=inp, outputs=out)
    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    return model
