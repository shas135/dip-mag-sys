import torch
import torch.nn as nn

class TransformerIDS(nn.Module):
    def __init__(self, input_dim=46, num_classes=6):
        super(TransformerIDS, self).__init__()
        self.input_fc = nn.Linear(input_dim, 512)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=512, nhead=8, dim_feedforward=512, batch_first=True
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=1)
        self.classifier = nn.Linear(512, num_classes)

    def forward(self, x):
        if x.dim() == 1: x = x.unsqueeze(0)
        x = self.input_fc(x).unsqueeze(1)
        x = self.encoder(x)
        x = x.mean(dim=1)
        return self.classifier(x)

def load_ids_model(model_path):
    model = TransformerIDS()
    checkpoint = torch.load(model_path, map_location='cpu', weights_only=False)
    # Checking for state_dict key
    state_dict = checkpoint["model_state_dict"] if "model_state_dict" in checkpoint else checkpoint
    model.load_state_dict(state_dict)
    model.eval()
    return model