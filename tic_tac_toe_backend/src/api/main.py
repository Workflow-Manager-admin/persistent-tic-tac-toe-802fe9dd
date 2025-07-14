from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional, Dict
from pydantic import BaseModel, Field
from uuid import uuid4
from datetime import datetime
from passlib.context import CryptContext
import secrets

# --- In-memory "databases" (for demo; replace with persistent DB in production) ---
USERS: Dict[str, dict] = {}  # username -> user data
TOKENS: Dict[str, str] = {}  # token -> username
GAMES: Dict[str, dict] = {}  # game_id -> game dict
LEADERBOARD: Dict[str, int] = {}  # username -> wins

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# FastAPI setup
app = FastAPI(
    title="Tic Tac Toe Backend API",
    description="Backend for multiplayer Tic Tac Toe game. Handles authentication, game management, moves, leaderboard, and history.",
    version="1.0.0",
    openapi_tags=[
        {"name": "auth", "description": "User authentication (register, login)"},
        {"name": "game", "description": "Game lifecycle and gameplay"},
        {"name": "leaderboard", "description": "Leaderboard and stats"},
        {"name": "history", "description": "User game history"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# =======================
#  MODELS
# =======================

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=30, description="Unique username")
    password: str = Field(..., min_length=6, description="Password (min 6 chars)")

class User(BaseModel):
    username: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class GameCreateRequest(BaseModel):
    board_size: int = Field(default=3, description="Game board size, default 3x3")

class GameState(BaseModel):
    game_id: str
    board: List[List[str]]
    player_x: Optional[str]
    player_o: Optional[str]
    next_turn: str
    winner: Optional[str]
    status: str
    created_at: datetime

class JoinGameRequest(BaseModel):
    game_id: str

class MoveRequest(BaseModel):
    game_id: str
    position_x: int
    position_y: int

class LeaderboardEntry(BaseModel):
    username: str
    wins: int

class GameHistoryEntry(BaseModel):
    game_id: str
    as_player: str
    opponent: Optional[str]
    started_at: datetime
    result: Optional[str]  # 'win', 'loss', 'draw', 'ongoing'

# =======================
#  UTILS
# =======================

# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password hash."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def authenticate_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Decode token and return user object. Raises 401 if invalid."""
    username = TOKENS.get(token)
    if not username or username not in USERS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    return USERS[username]

# =======================
#  AUTH ENDPOINTS
# =======================

@app.post("/register", response_model=User, tags=["auth"], summary="Register new user", description="Create a new user account.")
# PUBLIC_INTERFACE
def register(user: UserRegister):
    if user.username in USERS:
        raise HTTPException(status_code=409, detail="Username already exists")
    hashed_pw = hash_password(user.password)
    USERS[user.username] = {
        "username": user.username,
        "hashed_password": hashed_pw,
        "created_at": datetime.utcnow()
    }
    LEADERBOARD[user.username] = 0
    return User(username=user.username)

@app.post("/login", response_model=TokenResponse, tags=["auth"], summary="Login", description="Authenticate user and obtain access token")
# PUBLIC_INTERFACE
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    # Generate simple token; in production use JWT with expiry, etc.
    token = secrets.token_urlsafe(32)
    TOKENS[token] = form_data.username
    return TokenResponse(access_token=token)

# =======================
#  GAME LIFECYCLE/APIs
# =======================

@app.post("/game/create", response_model=GameState, tags=["game"], summary="Create new game", description="Create a new Tic Tac Toe game.")
# PUBLIC_INTERFACE
def create_game(game_req: GameCreateRequest, user=Depends(authenticate_user)):
    game_id = str(uuid4())
    size = game_req.board_size
    board = [["" for _ in range(size)] for _ in range(size)]
    game = {
        "game_id": game_id,
        "board": board,
        "player_x": user["username"],
        "player_o": None,
        "next_turn": "X",
        "winner": None,
        "status": "waiting",  # 'waiting', 'active', 'finished'
        "created_at": datetime.utcnow(),
        "moves": [],
    }
    GAMES[game_id] = game
    return _game_to_state(game)

@app.post("/game/join", response_model=GameState, tags=["game"], summary="Join a waiting game", description="Join an existing game as Player O.")
# PUBLIC_INTERFACE
def join_game(join_req: JoinGameRequest, user=Depends(authenticate_user)):
    game = GAMES.get(join_req.game_id)
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if game["player_o"] is not None:
        raise HTTPException(status_code=400, detail="Game already has 2 players")
    if game["player_x"] == user["username"]:
        raise HTTPException(status_code=400, detail="Cannot join your own game")
    game["player_o"] = user["username"]
    game["status"] = "active"
    return _game_to_state(game)

@app.get("/game/{game_id}", response_model=GameState, tags=["game"], summary="Game state", description="Retrieve the game board state and info.")
# PUBLIC_INTERFACE
def get_game_state(game_id: str, user=Depends(authenticate_user)):
    game = GAMES.get(game_id)
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if user["username"] not in [game["player_x"], game["player_o"]]:
        raise HTTPException(status_code=403, detail="Not a participant of this game")
    return _game_to_state(game)

@app.post("/game/move", response_model=GameState, tags=["game"], summary="Submit a move", description="Make a move in a game. Returns new game state.")
# PUBLIC_INTERFACE
def make_move(move: MoveRequest, user=Depends(authenticate_user)):
    game = GAMES.get(move.game_id)
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    if game["status"] != "active":
        raise HTTPException(status_code=400, detail="Game not active")
    symbol = None
    if user["username"] == game["player_x"]:
        symbol = "X"
    elif user["username"] == game["player_o"]:
        symbol = "O"
    else:
        raise HTTPException(status_code=403, detail="Not a participant of this game")

    size = len(game["board"])
    x, y = move.position_x, move.position_y
    if not (0 <= x < size and 0 <= y < size):
        raise HTTPException(status_code=400, detail="Invalid board position")
    if game["board"][x][y] != "":
        raise HTTPException(status_code=400, detail="Cell already occupied")
    if ((symbol == "X" and game["next_turn"] != "X") or
        (symbol == "O" and game["next_turn"] != "O")):
        raise HTTPException(status_code=400, detail="Not your turn")
    
    # Update board
    game["board"][x][y] = symbol
    game["moves"].append({
        "player": user["username"],
        "symbol": symbol,
        "x": x,
        "y": y,
        "moved_at": datetime.utcnow()
    })
    # Switch turn
    game["next_turn"] = "O" if symbol == "X" else "X"
    # Check for win
    winner = _check_winner(game)
    if winner:
        game["winner"] = winner
        game["status"] = "finished"
        # Update leaderboard
        if winner in LEADERBOARD:
            LEADERBOARD[winner] += 1
    elif _is_draw(game):
        game["winner"] = None
        game["status"] = "finished"
    return _game_to_state(game)

# =======================
#  LEADERBOARD
# =======================

@app.get("/leaderboard", response_model=List[LeaderboardEntry], tags=["leaderboard"], summary="Get leaderboard", description="Top users by win count.")
# PUBLIC_INTERFACE
def leaderboard():
    leaderboard = [LeaderboardEntry(username=u, wins=w) for u, w in sorted(LEADERBOARD.items(), key=lambda x: x[1], reverse=True)]
    return leaderboard

# =======================
#  USER HISTORY
# =======================

@app.get("/history", response_model=List[GameHistoryEntry], tags=["history"], summary="User's game history", description="List a user's recent games.")
# PUBLIC_INTERFACE
def game_history(user=Depends(authenticate_user)):
    user_games = []
    for game in GAMES.values():
        if user["username"] == game["player_x"]:
            as_player = "X"
            opponent = game["player_o"]
        elif user["username"] == game["player_o"]:
            as_player = "O"
            opponent = game["player_x"]
        else:
            continue
        result = None
        if game["status"] == "finished":
            if game["winner"] == user["username"]:
                result = "win"
            elif game["winner"] is None:
                result = "draw"
            else:
                result = "loss"
        else:
            result = "ongoing"
        user_games.append(GameHistoryEntry(
            game_id=game["game_id"],
            as_player=as_player,
            opponent=opponent,
            started_at=game["created_at"],
            result=result
        ))
    user_games.sort(key=lambda gh: gh.started_at, reverse=True)
    return user_games

# =======================
#  HEALTH CHECK (already present)
# =======================

@app.get("/", tags=["health"], summary="Health Check", description="Health check for service status.")
def health_check():
    return {"message": "Healthy"}

# =======================
#  HELPER FUNCTIONS (not APIs)
# =======================

def _check_winner(game) -> Optional[str]:
    board = game["board"]
    size = len(board)
    lines = []
    # Rows, cols, diag, anti-diag
    for i in range(size):
        lines.append(board[i])
        lines.append([board[j][i] for j in range(size)])
    lines.append([board[i][i] for i in range(size)])
    lines.append([board[i][size - 1 - i] for i in range(size)])
    for line in lines:
        if all(cell == "X" for cell in line):
            return game["player_x"]
        if all(cell == "O" for cell in line):
            return game["player_o"]
    return None

def _is_draw(game) -> bool:
    board = game["board"]
    return all(cell != "" for row in board for cell in row) and game["winner"] is None

def _game_to_state(game):
    return GameState(
        game_id=game["game_id"],
        board=game["board"],
        player_x=game["player_x"],
        player_o=game["player_o"],
        next_turn=game["next_turn"],
        winner=game["winner"],
        status=game["status"],
        created_at=game["created_at"]
    )
